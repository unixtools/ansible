#!/usr/bin/perl

use strict;
use Net::DNS;
use JSON;
use Getopt::Long;

$ENV{PATH} = "/usr/bin:/usr/local/bin:" . $ENV{PATH};
$ENV{HOME} = ( getpwuid($>) )[7];

my $debug   = 0;
my $onlyone = 0;
my $help    = 0;
my $dryrun  = 0;

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
    "help"        => \$help,
);
@regions = split( /,/, join( ',', @regions ) );

if ( !$res || $help || !$profile || !$zone || scalar(@regions) < 1 ) {
    print "Usage: $0 [--dryrun] [--debug] [--help] [--onlyone] --profile aws-cli-profile --zone route53-zone \n";
    print "   --region region1,region2 --region region3 --region region4\n";
    exit(1);
}

my @dryrun_echo = ();
if ($dryrun) {
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
my %instance_to_state   = ();

my %seen_name = ();

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

    my $curdns      = "";
    my $curinstance = "";
    my $curstate    = "";

    foreach my $rref ( sort { $a->{ReservationId} cmp $b->{ReservationId} } @{ $data->{Reservations} } ) {
        foreach my $iref ( sort { $a->{InstanceId} cmp $b->{InstanceId} } @{ $rref->{Instances} } ) {
            my $id = $iref->{InstanceId};

            if ( $iref->{State}->{Name} =~ /terminated/ ) {
                next;
            }

            if ( $iref->{State}->{Name} =~ /running/ ) {
                $instance_to_state{$id} = $iref->{State}->{Name};
            }

            my $lindex = $iref->{AmiLaunchIndex};

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

            my $niref   = $iref->{NetworkInterfaces}->[0];
            my $privdns = $niref->{PrivateIpAddresses}->[0]->{PrivateDnsName};

            my $pubdns = $niref->{Association}->{PublicDnsName};
            if ( !$pubdns ) {
                $debug && print "$curname: Falling back to other public dns name entry.\n";
                $pubdns = $iref->{PublicDnsName};
            }

            if ( !$privdns ) {
                $debug && print "Skipping $id, no instance private address/dns\n";
                next;
            }

            if ( $seen_name{$curname} ) {
                $debug && print "Skipping duplicate name: $curname for $id.\n";
            }
            else {
                $instance_to_fqdn{$id}    = $pubdns ? $pubdns : $privdns;
                $instance_to_private{$id} = $privdns;
                $instance_to_name{$id}    = $curname;
                $seen_name{$curname}      = 1;
            }

            $curname .= "-" . $lindex;
            if ( $seen_name{$curname} ) {
                print "Skipping duplicate name: $curname for ALT-$id.\n";
            }
            else {
                $instance_to_fqdn{ "ALT-" . $id }    = $pubdns ? $pubdns : $privdns;
                $instance_to_private{ "ALT-" . $id } = $privdns;
                $instance_to_name{ "ALT-" . $id }    = $curname;
                $seen_name{$curname}                 = 1;
            }
        }
    }
}

print "\n\n";
print "Processing DNS updates...\n";

my @creates   = ();
my @deletes   = ();
my @creates_a = ();
my @deletes_a = ();

my %seen_name = ();
foreach my $instance ( sort( keys(%instance_to_fqdn) ) ) {
    my $nm    = $instance_to_name{$instance};
    my $fqdn  = $instance_to_fqdn{$instance};
    my $state = $instance_to_state{$instance};

    next if ( $state !~ /running/ );

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

    if ( $fqdn =~ /^ip-\d+/o ) {
        print "\nError with public FQDN: $nm / $host\n";
        next;
    }

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
    my $query    = $dns->search($host);
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
    my $nm    = $instance_to_name{$instance};
    my $fqdn  = $instance_to_private{$instance};
    my $state = $instance_to_state{$instance};
    my $addr  = "";

    if ( $fqdn =~ /^ip-(\d+)-(\d+)-(\d+)-(\d+)\./o ) {
        $addr = "$1.$2.$3.$4";
    }

    if ( !$addr ) {

        # Skip host, no address
        next;
    }

    next if ( $state !~ /running/ );

    my $host    = $nm . "-int.$zone";
    my $wantttl = 30;
    if ( $nm =~ /mgmt/ || $nm =~ /mongo/ ) {
        $wantttl = 900;
    }

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
    my $query    = $dns->search($host);
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
    my $jsontext = $json->encode($req);

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
    my $jsontext = $json->encode($req);

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
    my $jsontext = $json->encode($req);

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
    my $jsontext = $json->encode($req);

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
