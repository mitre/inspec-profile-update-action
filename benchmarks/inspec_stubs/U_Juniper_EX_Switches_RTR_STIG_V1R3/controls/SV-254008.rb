control 'SV-254008' do
  title 'The Juniper P router must be configured to enforce a Quality-of-Service (QoS) policy in accordance with the QoS GIG Technical Profile.'
  desc 'Different applications have unique requirements and toleration levels for delay, jitter, bandwidth, packet loss, and availability. To manage the multitude of applications and services, a network requires a QoS framework to differentiate traffic and provide a method to manage network congestion. The Differentiated Services Model (DiffServ) is based on per-hop behavior by categorizing traffic into different classes and enabling each node to enforce a forwarding treatment to each packet as dictated by a policy.

Packet markings such as IP Precedence and its successor, Differentiated Services Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic, prioritizes it according to its relative importance, and provides priority treatment based on the classification. It is imperative that end-to-end QoS is implemented within the IP core network to provide preferred treatment for mission-critical applications.'
  desc 'check', 'Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications in accordance with the QoS GIG Technical Profile. 

Verify that the classifiers are configured to match on DSCP.
Note: Juniper routers also support classifying on MPLS EXP and IEEE 802.1 values. 

Verify that the schedulers are configured to set DSCP values for the defined classifiers in accordance with the QoS GIG Technical Profile. 

Verify that classifiers are applied all interfaces. 

Note: The GTP QOS document (GTP-0009) can be downloaded via the following link:
https://intellipedia.intelink.gov/wiki/Portal:GIG_Technical_Guidance/GTG_GTPs/GTP_Development_List

To classify on L4 ports or protocols, use stateless firewall filters to direct matched traffic into the required forwarding class.

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

If the router is not configured to implement a QoS policy in accordance with the QoS GIG Technical Profile, this is a finding.'
  desc 'fix', 'Configure a QoS policy on each router in accordance with the QoS GIG Technical Profile.

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
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57460r844055_chk'
  tag severity: 'low'
  tag gid: 'V-254008'
  tag rid: 'SV-254008r844057_rule'
  tag stig_id: 'JUEX-RT-000360'
  tag gtitle: 'SRG-NET-000193-RTR-000114'
  tag fix_id: 'F-57411r844056_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
