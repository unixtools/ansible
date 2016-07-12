#!/bin/sh

ed /etc/hosts <<EOF
g/127.0.1.1/d
.
w
q
EOF


