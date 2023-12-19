control 'SV-217081' do
  title 'The Juniper PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Verify that a forwarding class has been configured for the Scavenger class. CS1 has been adopted as the forwarding class; hence, the example below will define class CS1 to be used.

class-of-service {
    …
    …
    …
    }
    forwarding-classes {
        class CS1 queue-num 7 priority low;
    }

The Scavenger class is marked at the access layer with DSCP CS1. Hence, the router must maintain the marking and assign the packet to the configured forwarding class CS1.

PE Router only - Verify that the Multifield (MF) classifier has provisioned for this class as shown in the example below.

firewall {
    family inet {
        filter CLASSIFY_TRAFFIC {
            …
            …
            …
            }
            term SCAVENGER {
                from {
                    dscp cs1;
                }
                then {
                    forwarding-class CS1;
                    accept;
                }
            }
            term ACCEPT_OTHER {
                then {
                    forwarding-class best-effort;
                    accept;
                }
            }
        }
    }
}

PE and P router - Verify that a Behavior aggregate (BA) classifier has been configured to match the Scavenger class (CS1) as shown in the example below.

class-of-service {
    classifiers {
        dscp CLASSIFIER {
            import default;
            forwarding-class CS1 {
                loss-priority high code-points 001000;
            }
        }
    }

Note: A proactive approach to mitigating DoS and worm flooding attacks within the base/camp/agency enclaves is to respond immediately to out-of-profile network behavior indicative of a DoS or worm attack via access-Layer policers. Such policers can meter traffic rates received from endpoint devices.  When these traffic flows exceed specified rates, they no longer are considered normal flows and henceforth can be set to the Scavenger class marking (DSCP CS1).

P router – Verify that the BA classifier has been applied to all interfaces as shown in the example below.

class-of-service {
    …
    …
    …
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                classifiers {
                    dscp CLASSIFIER;
                }
            }
        }
        ge-0/1/1 {
            unit 0 {
                classifiers {
                    dscp CLASSIFIER;
                }
            }
        }
    }
}

Remaining steps only apply to the PE router.

Verify that a scheduler has been configured for the Scavenger class as shown in the example below.

class-of-service {
    …
    …
    …
    }
    schedulers {
        …
        …
        …
        }
        SCAVENGER_SCHED {
            transmit-rate percent 5;
            buffer-size percent 5;
            priority low;
        }
    }
}

Verify that the scheduler has been added to the scheduler map.

class-of-service {
    …
    …
    …
    }
    scheduler-maps {
        QOS_SCHED_MAP {
            forwarding-class expedited-forwarding scheduler VOIP_SCHED;
            forwarding-class network-control scheduler CONTROL_PLANE_SCHED;
            forwarding-class assured-forwarding scheduler MGMT_SCHED;
            forwarding-class best-effort scheduler BEST_EFFORT_SCHED;
            forwarding-class CS1 scheduler SCAVENGER_SCHED;
        }
    }

Verify that rewrite rules have been created to mark DSCP CS1 for those packets assigned to the Scavenger class with the appropriate code points.

class-of-service {
    …
    …
    …
    }
    rewrite-rules {
        dscp REWRITE_DSCP {
            import default;
            forwarding-class CS1 {
                loss-priority high code-point 001000;
            }
        }
    }

Verify that the scheduler map, rewrite rules, and the BA classifier has been applied to all core-facing interfaces.

class-of-service {
    …
    …
    …
    }
    interfaces {
        ge-2/1/1 {
            scheduler-map QOS_SCHED_MAP;
            unit 0 {
                classifiers {
                    dscp CLASSIFIER;
                }
                rewrite-rules {
                    dscp REWRITE_DSCP;
                }
            }
        }
        ge-2/0/1 {
            scheduler-map QOS_SCHED_MAP;
            unit 0 {
                rewrite-rules {
                    dscp REWRITE_DSCP;
                }
            }
        }
    }

If QoS policy to limit the effects of packet flooding denial-of-service (DoS) attacks has not been configured, this is a finding.'
  desc 'fix', 'Configure a forwarding class has been configured for the Scavenger class as shown in the example below.

[edit class-of-service forwarding-classes]
set class CS1 queue-num 7 priority low 

The Scavenger class is marked at the access layer with DSCP CS1. Hence, the router must maintain the marking and assign the packet to the configured forwarding class CS1.

PE Router only – Configure a Multifield (MF) classifier to provision for the Scavenger class as shown in the example below.

[edit firewall family inet filter CLASSIFY_TRAFFIC]
set term SCAVENGER from dscp cs1
set term SCAVENGER then forwarding-class CS1 accept
insert term SCAVENGER before term ACCEPT_OTHER

PE and P Router – Configure a Behavior aggregate (BA) classifier to match on the packets marked with DSCP CS1.

[edit class-of-service classifiers] 
set dscp CLASSIFIER import default forwarding-class CS1 loss-priority high code-points 001000 

P router only – Apply the BA classifier to all interfaces.

[edit class-of-service interfaces]
set ge-0/0/1 unit 0 classifiers dscp CLASSIFIER
set ge-0/1/1 unit 0 classifiers dscp CLASSIFIER

Remaining steps are only applicable to the PE router.

Configure a scheduler for the Scavenger class.

[edit class-of-service schedulers]
set SCAVENGER_SCHED transmit-rate percent 5
set SCAVENGER_SCHED buffer-size percent 5
set SCAVENGER_SCHED priority low
set BEST_EFFORT_SCHED transmit-rate percent 55

Add the Scavenger scheduler to the scheduler map.

[edit class-of-service scheduler-maps QOS_SCHED_MAP]
set forwarding-class CS1 scheduler SCAVENGER_SCHED

Apply the scheduler map to all core-facing interfaces.

[edit class-of-service interfaces]
set ge-2/1/1 scheduler-map QOS_SCHED_MAP
set ge-1/0/1 scheduler-map QOS_SCHED_MAP

Note: The above step should already have been completed.

Configure rewrite rules to ensure egress Scavenger packets will continue to be marked with DSCP CS1.

[edit class-of-service rewrite-rules]
set dscp REWRITE_DSCP import default forwarding-class CS1 loss-priority high code-point 001000 

Apply the configured rewrite rules to all core-facing interfaces.

[edit class-of-service interfaces]
set ge-2/1/1 unit 0 rewrite-rules dscp REWRITE_DSCP
set ge-1/0/1 unit 0 rewrite-rules dscp REWRITE_DSCP'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18310r297111_chk'
  tag severity: 'medium'
  tag gid: 'V-217081'
  tag rid: 'SV-217081r604135_rule'
  tag stig_id: 'JUNI-RT-000770'
  tag gtitle: 'SRG-NET-000193-RTR-000112'
  tag fix_id: 'F-18308r297112_fix'
  tag 'documentable'
  tag legacy: ['SV-101155', 'V-90945']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
