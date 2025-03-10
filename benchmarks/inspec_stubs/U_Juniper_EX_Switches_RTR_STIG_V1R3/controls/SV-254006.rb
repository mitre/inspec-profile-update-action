control 'SV-254006' do
  title 'The Juniper PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, QoS, or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the router configuration and interview the System Administrator to verify that a mechanism for traffic prioritization and bandwidth reservation exists. For example:

[edit class-of-service]
classifiers {
    dscp <classifier name> {
        forwarding-class NC {
            loss-priority low code-points 110000;
        }
        forwarding-class EF {
            loss-priority high code-points [ 101101 101111 100101 100111 110011 ];
            loss-priority low code-points [ 101000 100000 101001 101011 100001 100011 110001 ];
        }
        forwarding-class AF41 {
            loss-priority high code-points [ 100010 100100 100110 ];
            loss-priority low code-points [ 011000 101110 011100 011110 ];
        }
        forwarding-class AF31 {
            loss-priority high code-points [ 011101 011111 011010 010101 010111 010010 001101 001010 010000 ];
            loss-priority low code-points [ 001001 001011 010001 010011 011001 011011 ];
        }
        forwarding-class BE {
            loss-priority high code-points 000000;
        }
        forwarding-class Default {
            loss-priority high code-points 001000;
        }
        forwarding-class dscp15 {
            loss-priority high code-points 001111;
        }
    }
}

Note: Some platforms apply DSCP values to both IPv4 and IPv6 traffic with a single classifier definition (as shown). Those platforms that support separating classifiers will require a "dscp-ipv6" stanza.
host-outbound-traffic {
    forwarding-class NC;
    dscp-code-point 110000;
}
shared-buffer {
    ingress {
        percent 50;
        buffer-partition lossless {
            percent 5;
        }
        buffer-partition lossless-headroom {
            percent 0;
        }
        buffer-partition lossy {
            percent 95;
        }
    }
    egress {
        percent 100;
        buffer-partition lossless {
            percent 50;
        }
        buffer-partition lossy {
            percent 45;
        }
        buffer-partition multicast {
            percent 5;
        }
    }
}
Note: Some platforms only support shared-buffer percent, and cannot separate between ingress and egress. Not all devices require a shared-buffer stanza.
forwarding-classes {
    class NC queue-num 7;
    class EF queue-num 6;
    class AF41 queue-num 5;
    class AF31 queue-num 4;
    class BE queue-num 0;
    class Default queue-num 1;
    class dscp15 queue-num 6;
}
traffic-control-profiles {
    <control profile name 1> {
        scheduler-map <scheduler map name 1>;        
        shaping-rate percent 100;
    }
    <control profile name 2> {
        scheduler-map <scheduler map name 2>;
        guaranteed-rate percent 20;
    }
}
forwarding-class-sets {
    <set name 1> {
        class NC;
        class EF;
        class AF41;
        class AF31;
        class Default;
        class dscp15;
    }
    <set name 2> {
        class BE;
    }
}
interfaces {
    <interface name> {
        forwarding-class-set {
            <set name 1> {
                output-traffic-control-profile <control profile name 1>;
            }
            <set name 2> {
                output-traffic-control-profile <control profile name 2>;
            }
        }
        classifiers {
            dscp <classifier name>;
        }
        rewrite-rules {
            dscp <rewrite rule name>;
        }
    }
}
rewrite-rules {
    dscp <rewrite rule name> {
        forwarding-class dscp15 {
            loss-priority high code-point 101101;
        }
        forwarding-class EF {
            loss-priority low code-point 110001;
        }
        forwarding-class AF41 {
            loss-priority high code-point 100110;
        }
        forwarding-class NC {
            loss-priority low code-point 110000;
        }
        forwarding-class AF31 {
            loss-priority high code-point 010000;
        }
        forwarding-class Default {
            loss-priority high code-point 001000;
        }
    }
}
Note: Some platforms require rewriting all DSCP values if rewriting one (smaller platforms). Most support only rewriting a single DSCP value, which would eliminate all but one rewrite rule.
scheduler-maps {
    <scheduler map name 1> {
        forwarding-class NC scheduler NC;
        forwarding-class EF scheduler EF;
        forwarding-class AF41 scheduler AF41;
        forwarding-class AF31 scheduler AF31;
        forwarding-class Default scheduler Default;
    }
    <scheduler map name 2> {
        forwarding-class BE scheduler BE;
    }
}
schedulers {
    NC {
        buffer-size percent 5;
        priority strict-high;
    }
    EF {
        shaping-rate percent 20;
        buffer-size percent 19;
        priority strict-high;
    }
    AF41 {
        shaping-rate percent 15;
        buffer-size percent 14;
        priority strict-high;
    }
    AF31 {
        shaping-rate percent 31;
        buffer-size percent 29;
        priority strict-high;
    }
    BE {
        transmit-rate percent 20;
        buffer-size percent 20;
        priority low;
    }
    Default {
        shaping-rate percent 10;
        buffer-size percent 9;
        priority strict-high;
    }
}

This arrangement must ensure that sufficient capacity is available for mission-critical traffic and enforce the traffic priorities specified by the Combatant Commands/Services/Agencies.

If no such scheme exists or it is not configured, this is a finding.'
  desc 'fix', 'Implement a mechanism for traffic prioritization and bandwidth reservation. This mechanism must enforce the traffic priorities specified by the Combatant Commands/Services/Agencies.

set class-of-service classifiers dscp <classifier name> forwarding-class NC loss-priority low code-points 110000
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority high code-points 101101
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority high code-points 101111
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority high code-points 100101
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority high code-points 100111
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority high code-points 110011
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority low code-points 101000
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority low code-points 100000
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority low code-points 101001
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority low code-points 101011
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority low code-points 100001
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority low code-points 100011
set class-of-service classifiers dscp <classifier name> forwarding-class EF loss-priority low code-points 110001
set class-of-service classifiers dscp <classifier name> forwarding-class AF41 loss-priority high code-points 100010
set class-of-service classifiers dscp <classifier name> forwarding-class AF41 loss-priority high code-points 100100
set class-of-service classifiers dscp <classifier name> forwarding-class AF41 loss-priority high code-points 100110
set class-of-service classifiers dscp <classifier name> forwarding-class AF41 loss-priority low code-points 011000
set class-of-service classifiers dscp <classifier name> forwarding-class AF41 loss-priority low code-points 101110
set class-of-service classifiers dscp <classifier name> forwarding-class AF41 loss-priority low code-points 011100
set class-of-service classifiers dscp <classifier name> forwarding-class AF41 loss-priority low code-points 011110
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 011101
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 011111
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 011010
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 010101
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 010111
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 010010
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 001101
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 001010
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority high code-points 010000
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority low code-points 001001
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority low code-points 001011
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority low code-points 010001
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority low code-points 010011
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority low code-points 011001
set class-of-service classifiers dscp <classifier name> forwarding-class AF31 loss-priority low code-points 011011
set class-of-service classifiers dscp <classifier name> forwarding-class BE loss-priority high code-points 000000
set class-of-service classifiers dscp <classifier name> forwarding-class Default loss-priority high code-points 001000
set class-of-service classifiers dscp <classifier name> forwarding-class dscp15 loss-priority high code-points 001111
Note: Some platforms apply DSCP values to both IPv4 and IPv6 traffic with a single classifier definition (as shown). Those platforms that support separating classifiers will require a "dscp-ipv6" stanza.

set class-of-service host-outbound-traffic forwarding-class NC
set class-of-service host-outbound-traffic dscp-code-point 110000
set class-of-service shared-buffer ingress percent 50
set class-of-service shared-buffer ingress buffer-partition lossless percent 5
set class-of-service shared-buffer ingress buffer-partition lossless-headroom percent 0
set class-of-service shared-buffer ingress buffer-partition lossy percent 95
set class-of-service shared-buffer egress percent 100
set class-of-service shared-buffer egress buffer-partition lossless percent 50
set class-of-service shared-buffer egress buffer-partition lossy percent 45
set class-of-service shared-buffer egress buffer-partition multicast percent 5
Note: Some platforms only support shared-buffer percent, and cannot separate between ingress and egress. Not all devices require a shared-buffer stanza.

set class-of-service forwarding-classes class NC queue-num 7
set class-of-service forwarding-classes class EF queue-num 6
set class-of-service forwarding-classes class AF41 queue-num 5
set class-of-service forwarding-classes class AF31 queue-num 4
set class-of-service forwarding-classes class BE queue-num 0
set class-of-service forwarding-classes class Default queue-num 1
set class-of-service forwarding-classes class dscp15 queue-num 6

set class-of-service traffic-control-profiles <control profile name 1> scheduler-map <scheduler map name 1>
set class-of-service traffic-control-profiles <control profile name 1> shaping-rate percent 100
set class-of-service traffic-control-profiles <control profile name 2> scheduler-map <scheduler map name 2>
set class-of-service traffic-control-profiles <control profile name 2> guaranteed-rate percent 20

set class-of-service forwarding-class-sets <set name 1> class NC
set class-of-service forwarding-class-sets <set name 1> class EF
set class-of-service forwarding-class-sets <set name 1> class AF41
set class-of-service forwarding-class-sets <set name 1> class AF31
set class-of-service forwarding-class-sets <set name 1> class Default
set class-of-service forwarding-class-sets <set name 1> class dscp15
set class-of-service forwarding-class-sets <set name 2> class BE

set class-of-service interfaces <interface name> forwarding-class-set <set name 1> output-traffic-control-profile <control profile name 1>
set class-of-service interfaces <interface name> forwarding-class-set <set name 2> output-traffic-control-profile <control profile name 2>
set class-of-service interfaces <interface name> classifiers dscp <classifier name>
set class-of-service interfaces <interface name> rewrite-rules dscp <rewrite rule name>

set class-of-service rewrite-rules dscp <rewrite rule name> forwarding-class dscp15 loss-priority high code-point 101101
set class-of-service rewrite-rules dscp <rewrite rule name> forwarding-class EF loss-priority low code-point 110001
set class-of-service rewrite-rules dscp <rewrite rule name> forwarding-class AF41 loss-priority high code-point 100110
set class-of-service rewrite-rules dscp <rewrite rule name> forwarding-class NC loss-priority low code-point 110000
set class-of-service rewrite-rules dscp <rewrite rule name> forwarding-class AF31 loss-priority high code-point 010000
set class-of-service rewrite-rules dscp <rewrite rule name> forwarding-class Default loss-priority high code-point 001000

set class-of-service scheduler-maps <scheduler map name 1> forwarding-class NC scheduler NC
set class-of-service scheduler-maps <scheduler map name 1> forwarding-class EF scheduler EF
set class-of-service scheduler-maps <scheduler map name 1> forwarding-class AF41 scheduler AF41
set class-of-service scheduler-maps <scheduler map name 1> forwarding-class AF31 scheduler AF31
set class-of-service scheduler-maps <scheduler map name 1> forwarding-class Default scheduler Default
set class-of-service scheduler-maps <scheduler map name 2> forwarding-class BE scheduler BE

set class-of-service schedulers NC buffer-size percent 5
set class-of-service schedulers NC priority strict-high
set class-of-service schedulers EF shaping-rate percent 20
set class-of-service schedulers EF buffer-size percent 19
set class-of-service schedulers EF priority strict-high
set class-of-service schedulers AF41 shaping-rate percent 15
set class-of-service schedulers AF41 buffer-size percent 14
set class-of-service schedulers AF41 priority strict-high
set class-of-service schedulers AF31 shaping-rate percent 31
set class-of-service schedulers AF31 buffer-size percent 29
set class-of-service schedulers AF31 priority strict-high
set class-of-service schedulers BE transmit-rate percent 20
set class-of-service schedulers BE buffer-size percent 20
set class-of-service schedulers BE priority low
set class-of-service schedulers Default shaping-rate percent 10
set class-of-service schedulers Default buffer-size percent 9
set class-of-service schedulers Default priority strict-high'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57458r844049_chk'
  tag severity: 'medium'
  tag gid: 'V-254006'
  tag rid: 'SV-254006r844051_rule'
  tag stig_id: 'JUEX-RT-000340'
  tag gtitle: 'SRG-NET-000193-RTR-000112'
  tag fix_id: 'F-57409r844050_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
