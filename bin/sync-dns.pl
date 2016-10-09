#!/usr/bin/perl

use strict;
use Net::DNS;
use JSON;
use Getopt::Long;

$ENV{PATH} = "/usr/bin:/usr/local/bin:" . $ENV{PATH};
$ENV{HOME} = ( getpwuid($>) )[7];

my $debug               = 0;
my $onlyone             = 0;
my $help                = 0;
my $dryrun              = 0;
my $direct_dns_fallback = 0;
my $clean               = 0;
my $saferclean          = 0;

my $profile;
my $zone;
my @regions;

my $res = GetOptions(
    "onlyone"     => \$onlyone,
    "debug+"      => \$debug,
    "dryrun|n+"   => \$dryrun,
    "profile=s"   => \$profile,
    "zone=s"      => \$zone,
    "regions=s\@" => \@regions,
    "fallback+"   => \$direct_dns_fallback,
    "clean+"      => \$clean,
    "saferclean+" => \$saferclean,
    "help"        => \$help,
);
@regions = split( /,/, join( ',', @regions ) );

if ( !$res || $help || !$profile || !$zone || scalar(@regions) < 1 ) {
    print
        "Usage: $0 [--dryrun] [--debug] [--help] [--onlyone] [--fallback] [--clean] [--saferclean] --profile aws-cli-profile --zone route53-zone \n";
    print "   --region region1,region2 --region region3 --region region4\n";
    exit(1);
}

my @dryrun_echo = ();
if ($dryrun) {
    print "DRY RUN, NOT PERFORMING UPDATES!\n";
    @dryrun_echo = ("echo");
}

my $json = new JSON;
$json->canonical(1);

# First retrieve the zone list to obtain details
print "Scanning hosted zone list...\n";
open( my $in, "-|" ) || exec( "aws", "--profile" => $profile, "route53" => "list-hosted-zones", "--output" => "json" );
my $json_in = join( "", <$in> );
close($in);

my $data = ();
eval { $data = decode_json($json_in); };
if ($@) {
    exit;
}

my $zone_id;
foreach my $zoneref ( @{ $data->{HostedZones} } ) {
    my $zonematch = $zone . ".";
    if ( lc( $zoneref->{Name} ) eq lc($zonematch) ) {
        $zone_id = $zoneref->{Id};
        $zone_id =~ s|.*/||go;
        last;
    }
}
if ( !$zone_id ) {
    die "Couldn't find zone ($zone).\n";
}
print "Zone ID: $zone_id\n";

#
# Now determine the set of root nameservers
#
print "Scanning nameservers for zone...\n";
open( my $in, "-|" )
    || exec( "aws", "--profile" => $profile, "route53" => "get-hosted-zone", "--id" => $zone_id, "--output" => "json" );
my $json_in = join( "", <$in> );
close($in);

my $data = ();
eval { $data = decode_json($json_in); };
if ($@) {
    exit;
}

my @nameservers = ();
my @nameservers = @{ $data->{DelegationSet}->{NameServers} };
if ( scalar(@nameservers) < 1 ) {
    die "Couldn't determine nameservers for $zone/$zone_id...\n";
}
else {
    print "Name Servers: ", join( " ", @nameservers ), "\n";
}

# Use the root NS for the zone to resolve without caching
my $dns = Net::DNS::Resolver->new( nameservers => [@nameservers] );
$dns->tcp_timeout(5);
$dns->udp_timeout(5);
$dns->persistent_tcp(1);
$dns->persistent_udp(1);

# Load in list of instances to get the ec2- target hostname
my %instance_to_fqdn    = ();
my %instance_to_private = ();
my %fqdn_to_instance    = ();
my %instance_to_name    = ();
my %name_to_instance    = ();
my %seen_name           = ();

# Process through each region list of instances tracking
# count of times seen each base hostname

# Process through the combined list of instances
my $all_instances     = {};
my $count_by_basename = {};
my $id_to_basename    = {};

foreach my $region (@regions) {
    print "Processing instances in region: $region\n";

    # Live load the instance info
    open( my $in, "-|" ) || exec(
        "aws",
        "--profile" => $profile,
        "--region"  => $region,
        "ec2"       => "describe-instances",
        "--output"  => "json"
    );
    my $json_in = join( "", <$in> );
    close($in);

    my $data = ();
    eval { $data = decode_json($json_in); };
    if ($@) {
        die $@;
    }

    foreach my $rref ( sort { $a->{ReservationId} cmp $b->{ReservationId} } @{ $data->{Reservations} } ) {
        foreach my $iref ( sort { $a->{InstanceId} cmp $b->{InstanceId} } @{ $rref->{Instances} } ) {
            my $id = $iref->{InstanceId};

            if ( $iref->{State}->{Name} =~ /terminated/ ) {
                next;
            }

            #if ( $iref->{State}->{Name} =~ /running/ ) {
            #    $instance_to_state{$id} = $iref->{State}->{Name};
            #}

            my %tags = ();
            foreach my $tref ( @{ $iref->{Tags} } ) {
                $tags{ $tref->{Key} } = $tref->{Value};
            }

            my $curname = $tags{DNSName} || $tags{Name};
            $curname = lc $curname;
            $curname =~ s/[^a-z0-9]/-/go;

            if ( !$curname ) {
                print "Cannot determine name for $id, skipping.\n";
                next;
            }

            $curname =~ s/--+/-/go;
            $curname = substr( $curname, 0, 50 );

            $id_to_basename->{$id} = $curname;
            $count_by_basename->{$curname}++;
            $all_instances->{$id} = $iref;

            $debug && print "$id: $curname (", $count_by_basename->{$curname}, ")\n";
        }
    }
}

# Process through the combined list of instances
print "Processing instances in all selected regions:\n";
my $times_seen_basename = {};

foreach my $id (
    sort {
               $all_instances->{$a}->{LaunchTime} cmp $all_instances->{$b}->{LaunchTime}
            || $all_instances->{$a}->{AmiLaunchIndex} cmp $all_instances->{$b}->{AmiLaunchIndex}
            || $all_instances->{$a}->{InstanceId} cmp $all_instances->{$b}->{InstanceId}
    } keys %{$all_instances}
    )
{

    my $iref    = $all_instances->{$id};
    my $curname = $id_to_basename->{$id};

    my $niref   = $iref->{NetworkInterfaces}->[0];
    my $privdns = $niref->{PrivateIpAddresses}->[0]->{PrivateDnsName};
    if ( !$privdns ) {
        $debug && print "$curname: Falling back to legacy private dns name entry.\n";
        $privdns = $iref->{PrivateDnsName};
    }

    my $pubdns = $niref->{Association}->{PublicDnsName};
    if ( !$pubdns ) {
        $debug && print "$curname: Falling back to legacy public dns name entry.\n";
        $pubdns = $iref->{PublicDnsName};
    }

    if ( !$privdns ) {
        $debug && print "Skipping $id, no instance private address/dns\n";
        next;
    }

    # First entry is only one to get assigned by basename
    if ( $times_seen_basename->{$curname} == 0 ) {
        $instance_to_fqdn{$id}    = $pubdns ? $pubdns : $privdns;
        $instance_to_private{$id} = $privdns;
        $instance_to_name{$id}    = $curname;
        $seen_name{$curname}      = 1;
    }
    else {
        $debug && print "$curname: already seen one instance, not assigning base dns entry.\n";
    }

    # If we have duplicates, assign suffix based on number of index of duplicate starting
    # at 0 for the first occurrence

    if ( $count_by_basename->{$curname} > 1 ) {
        my $idx = int( $times_seen_basename->{$curname} );

        my $altname = $curname;
        $altname = substr( $altname, 0, 47 );
        $altname .= "-" . $idx;

        if ( $seen_name{$altname} ) {
            print "Skipping duplicate name: $altname for ALT-$id.\n";
        }
        else {
            $instance_to_fqdn{ "ALT-" . $id }    = $pubdns ? $pubdns : $privdns;
            $instance_to_private{ "ALT-" . $id } = $privdns;
            $instance_to_name{ "ALT-" . $id }    = $altname;
            $seen_name{$altname}                 = 1;
        }
    }

    $times_seen_basename->{$curname}++;
}

#
# Prefetch existing zone from Route53
#
my $cur_dns_entries = {};
my $done_fetch      = 0;
my $page_token;
my $cnt = 0;
while ( !$done_fetch ) {
    print "Fetching a page of current DNS entries...\n";

    my @cmd = (
        "aws",
        "--profile"        => $profile,
        "route53"          => "list-resource-record-sets",
        "--hosted-zone-id" => $zone_id,
        "--output"         => "json",
    );
    if ($page_token) {
        push( @cmd, "--starting-token" => $page_token );
    }

    print "+ ", join( " ", @cmd ), "\n";
    open( my $in, "-|" ) || exec(@cmd);
    my $json_in = join( "", <$in> );
    close($in);

    my $data = ();
    eval { $data = decode_json($json_in); };
    if ($@) {
        die $@;
    }

    foreach my $rrset ( @{ $data->{ResourceRecordSets} } ) {
        my $name = $rrset->{Name};

        # Strip trailing .
        $name =~ s/\.$//go;

        my $type = $rrset->{Type};
        $cur_dns_entries->{$name}->{$type}->{ttl} = $rrset->{TTL};
        foreach my $rr ( @{ $rrset->{ResourceRecords} } ) {
            push( @{ $cur_dns_entries->{$name}->{$type}->{"values"} }, $rr->{Value} );
            $cnt++;
        }
    }
    if ( $data->{NextToken} ) {
        $page_token = $data->{NextToken};
    }
    else {
        $done_fetch = 1;
    }
    print "  Total count loaded so far: $cnt\n";
}
print "Done.\n";

# Track names we want
my $wanted_hosts = {};

print "\n\n";
print "Processing DNS updates...\n";

my @creates   = ();
my @deletes   = ();
my @creates_a = ();
my @deletes_a = ();

my %seen_name = ();
foreach my $instance ( sort( keys(%instance_to_fqdn) ) ) {
    my $nm   = $instance_to_name{$instance};
    my $fqdn = $instance_to_fqdn{$instance};

    if ( $seen_name{$nm} ) {
        print "Skipping duplicate name ($nm).\n";
        $seen_name{$nm} = 1;
        next;
    }

    my $host    = $nm . "." . $zone;
    my $wantttl = 30;
    if ( $nm =~ /mgmt/ || $nm =~ /mongo/ ) {
        $wantttl = 900;
    }

    $wanted_hosts->{$host} = 1;

    if ( !$fqdn ) {
        print "Cannot determine target fqdn for $host, skipping.\n";
    }

    $debug && print "\nProcessing host: $nm / $host:\n";
    if ( $nm !~ /^[a-z0-9\-]+$/o ) {
        print "  Unable to handle host name ($nm) for host ($host) instance ($instance) fqdn ($fqdn)\n";
        next;
    }

    $debug && print "  Want ${host} -> ${fqdn}\n";

    my $gotcname = "";
    my $gotttl   = 90;
    my $gota     = "";

    if ( $cur_dns_entries->{$host}->{CNAME} ) {
        $gotttl   = $cur_dns_entries->{$host}->{CNAME}->{ttl};
        $gotcname = $cur_dns_entries->{$host}->{CNAME}->{"values"}->[0];
    }
    elsif ( $cur_dns_entries->{$host}->{A} ) {
        $gotttl = $cur_dns_entries->{$host}->{A}->{ttl};
        $gota   = $cur_dns_entries->{$host}->{A}->{"values"}->[0];
    }
    elsif ($direct_dns_fallback) {
        print "$host not found in prefetch, attempting DNS query...\n";

        my $query = $dns->search($host);
        if ($query) {
            foreach my $rr ( $query->answer ) {
                if ( $rr->type eq "CNAME" ) {
                    $gotcname = $rr->cname;
                    $gotttl   = $rr->ttl;
                    last;
                }
                elsif ( $rr->type eq "A" ) {
                    $gota   = $rr->address;
                    $gotttl = $rr->ttl;
                }
            }
        }
    }

    if ( $gota && !$gotcname ) {
        print "  Host ${host} has A record ($gota), but no cname, leaving alone!\n";
        next;
    }

    if ($gotcname) {
        $debug && print "  Have ${host} -> ${gotcname}\n";

        if ( $gotcname ne $fqdn || $gotttl ne $wantttl ) {
            print "  UPDATE [$host]: change to $fqdn / $wantttl from $gotcname / $gotttl\n";
            push( @deletes, [ $host, $gotcname, $gotttl ] );
            push( @creates, [ $host, $fqdn,     $wantttl ] );
        }
    }
    else {
        print "   UPDATE [$host]: add cname pointing to $fqdn\n";
        push( @creates, [ $host, $fqdn, $wantttl ] );
    }

}

foreach my $instance ( sort( keys(%instance_to_fqdn) ) ) {
    my $nm   = $instance_to_name{$instance};
    my $fqdn = $instance_to_private{$instance};
    my $addr = "";

    if ( $fqdn =~ /^ip-(\d+)-(\d+)-(\d+)-(\d+)\./o ) {
        $addr = "$1.$2.$3.$4";
    }

    if ( !$addr ) {

        # Skip host, no address
        next;
    }

    my $host    = $nm . "-int.$zone";
    my $wantttl = 30;
    if ( $nm =~ /mgmt/ || $nm =~ /mongo/ ) {
        $wantttl = 900;
    }

    $wanted_hosts->{$host} = 1;

    $debug && print "\nProcessing host: $nm / $host:\n";
    if ( $nm !~ /^[a-z0-9\-]+$/o ) {
        print "  Unable to handle host name ($nm) for host ($host) instance ($instance) fqdn ($fqdn)\n";
        next;
    }

    if ( !$addr ) {
        print "  Cannot determine addr for host ($host) from ($fqdn).\n";
        next;
    }

    $debug && print "  Want ${host} -> ${addr}\n";

    my $gotcname = "";
    my $gotttl   = 90;
    my $gota     = "";

    if ( $cur_dns_entries->{$host}->{CNAME} ) {
        $gotttl   = $cur_dns_entries->{$host}->{CNAME}->{ttl};
        $gotcname = $cur_dns_entries->{$host}->{CNAME}->{"values"}->[0];
    }
    elsif ( $cur_dns_entries->{$host}->{A} ) {
        $gotttl = $cur_dns_entries->{$host}->{A}->{ttl};
        $gota   = $cur_dns_entries->{$host}->{A}->{"values"}->[0];
    }
    elsif ($direct_dns_fallback) {
        print "$host not found in prefetch, attempting DNS query...\n";
        my $query = $dns->search($host);
        if ( 0 && $query ) {
            foreach my $rr ( $query->answer ) {
                if ( $rr->type eq "CNAME" ) {
                    $gotcname = $rr->cname;
                    $gotttl   = $rr->ttl;
                    last;
                }
                elsif ( $rr->type eq "A" ) {
                    $gota   = $rr->address;
                    $gotttl = $rr->ttl;
                }
            }
        }
    }

    if ( !$gota && $gotcname ) {
        print "  Host ${host} has CNAME record ($gota), but no A, leaving alone!\n";
        next;
    }

    if ($gota) {
        $debug && print "  Have ${host} -> ${gota}\n";

        if ( $gota ne $addr || $gotttl ne $wantttl ) {
            print "  UPDATE [$host]: change to $addr / $wantttl from $gota / $gotttl\n";
            push( @deletes_a, [ $host, $gota, $gotttl ] );
            push( @creates_a, [ $host, $addr, $wantttl ] );
        }
    }
    else {
        print "   UPDATE [$host]: add A pointing to $addr\n";
        push( @creates_a, [ $host, $addr, $wantttl ] );
    }
}

if ( $clean || $saferclean ) {
    foreach my $host ( sort keys %{$cur_dns_entries} ) {
        next if ( $wanted_hosts->{$host} );

        if ( $cur_dns_entries->{$host}->{CNAME} ) {
            my $ttl = $cur_dns_entries->{$host}->{CNAME}->{ttl};
            foreach my $addr ( @{ $cur_dns_entries->{$host}->{CNAME}->{"values"} } ) {
                if ($saferclean) {
                    next if ( $addr !~ /^ec2-\d+-\d+-\d+-\d+/o );
                }
                print "   CLEAN [$host]: cleaning unwanted CNAME record ($addr).\n";
                push( @deletes, [ $host, $addr, $ttl ] );
            }
        }
        elsif ( $cur_dns_entries->{$host}->{A} ) {
            my $ttl = $cur_dns_entries->{$host}->{A}->{ttl};
            foreach my $addr ( @{ $cur_dns_entries->{$host}->{A}->{"values"} } ) {
                if ($saferclean) {
                    next if ( $addr !~ /^(10|172)\.\d+\.\d+\.\d+$/o );
                }
                print "   CLEAN [$host]: cleaning unwanted A record ($addr).\n";
                push( @deletes_a, [ $host, $addr, $ttl ] );
            }
        }
    }
}

my $cmds = 0;

foreach my $delete (@deletes) {
    my ( $host, $target, $ttl ) = @{$delete};
    next if ( $cmds > 0 && $onlyone );

    my $json = new JSON;
    my $req  = {
        "Changes" => [
            {   "Action"            => "DELETE",
                "ResourceRecordSet" => {
                    "Name"            => $host,
                    "Type"            => "CNAME",
                    "TTL"             => int($ttl),
                    "ResourceRecords" => [ { "Value" => $target } ],
                }
            }
        ]
    };
    my $jsontext = $json->canonical->encode($req);

    &mysystem(
        @dryrun_echo,
        "aws",
        "--profile"        => $profile,
        "route53"          => "change-resource-record-sets",
        "--hosted-zone-id" => $zone_id,
        "--change-batch"   => $jsontext
    );

    $cmds++;
}

foreach my $create (@creates) {
    my ( $host, $target, $ttl ) = @{$create};
    next if ( $cmds > 0 && $onlyone );

    my $json = new JSON;
    my $req  = {
        "Changes" => [
            {   "Action"            => "UPSERT",
                "ResourceRecordSet" => {
                    "Name"            => $host,
                    "Type"            => "CNAME",
                    "TTL"             => int($ttl),
                    "ResourceRecords" => [ { "Value" => $target } ],
                }
            }
        ]
    };
    my $jsontext = $json->canonical->encode($req);

    &mysystem(
        @dryrun_echo,
        "aws",
        "--profile"        => $profile,
        "route53"          => "change-resource-record-sets",
        "--hosted-zone-id" => $zone_id,
        "--change-batch"   => $jsontext
    );

    $cmds++;
}

foreach my $delete (@deletes_a) {
    my ( $host, $target, $ttl ) = @{$delete};
    next if ( $cmds > 0 && $onlyone );

    my $json = new JSON;
    my $req  = {
        "Changes" => [
            {   "Action"            => "DELETE",
                "ResourceRecordSet" => {
                    "Name"            => $host,
                    "Type"            => "A",
                    "TTL"             => int($ttl),
                    "ResourceRecords" => [ { "Value" => $target } ],
                }
            }
        ]
    };
    my $jsontext = $json->canonical->encode($req);

    &mysystem(
        @dryrun_echo,
        "aws",
        "--profile"        => $profile,
        "route53"          => "change-resource-record-sets",
        "--hosted-zone-id" => $zone_id,
        "--change-batch"   => $jsontext
    );

    $cmds++;
}

foreach my $create (@creates_a) {
    my ( $host, $target, $ttl ) = @{$create};
    next if ( $cmds > 0 && $onlyone );

    my $json = new JSON;
    my $req  = {
        "Changes" => [
            {   "Action"            => "UPSERT",
                "ResourceRecordSet" => {
                    "Name"            => $host,
                    "Type"            => "A",
                    "TTL"             => int($ttl),
                    "ResourceRecords" => [ { "Value" => $target } ],
                }
            }
        ]
    };
    my $jsontext = $json->canonical->encode($req);

    &mysystem(
        @dryrun_echo,
        "aws",
        "--profile"        => $profile,
        "route53"          => "change-resource-record-sets",
        "--hosted-zone-id" => $zone_id,
        "--change-batch"   => $jsontext
    );

    $cmds++;
}

sub mysystem {
    my @cmd = @_;
    print "+ ", join( " ", @cmd ), "\n";
    if ( !$dryrun ) {
        system(@cmd);
    }
}
