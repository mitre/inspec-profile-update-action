control 'SV-254031' do
  title 'The Juniper router must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by employing control plane protection.'
  desc 'The Routing Engine (RE) is critical to all network operations because it is the component used to build all forwarding paths for the data plane via control plane processes. It is also instrumental with ongoing network management functions that keep the routers and links available for providing network services. Any disruption to the RE or the control and management planes can result in mission-critical network outages.

A DoS attack targeting the RE can result in excessive CPU and memory utilization. To maintain network stability and RE security, the router must be able to handle specific control plane and management plane traffic that is destined to the RE. In the past, one method of filtering was to use ingress filters on forwarding interfaces to filter both forwarding path and receiving path traffic. However, this method does not scale well as the number of interfaces grows and the size of the ingress filters grows. Control plane policing increases the security of routers and multilayer switches by protecting the RE from unnecessary or malicious traffic. Filtering and rate limiting the traffic flow of control plane packets can be implemented to protect routers against reconnaissance and DoS attacks, allowing the control plane to maintain packet forwarding and protocol states despite an attack or heavy load on the router or multilayer switch.'
  desc 'check', 'Determine whether control plane protection has been implemented on the device by verifying traffic types have been classified based on importance levels and a policy has been configured to filter and rate limit the traffic according to each class.

Verify firewall filters include policers (rate limiting) based upon importance levels. Although the policer names shown in the example are the bandwidth limit, any legal name can be used.

[edit firewall]
family inet {
    filter <name> {
        term accept-tcp-initial {
            from {
                source-prefix-list {
                    management-networks-ipv4;
                }
                destination-prefix-list {
                    router-addresses-ipv4;
                }
                protocol tcp;
                destination-port ssh;
                tcp-initial;
            }
            then {
                policer policer-32k; << Lower rate for connection attempts to help prevent SYN flood attacks.
                accept;
            }
        }
        term accept-ssh {
            from {
                source-prefix-list {
                    management-networks-ipv4;
                }
                destination-prefix-list {
                    router-addresses-ipv4;
                }
                protocol tcp;
                destination-port ssh;
            }
            then {
                policer policer-1g; << Higher rate after connection establishment for remote management and/or secure file transfer.
                accept;
            }
        }
        term accept-snmp {
            from {
                source-prefix-list {
                    snmp-servers-ipv4;
                }
                destination-prefix-list {
                    router-addresses-ipv4;
                }
                protocol udp;
                destination-port snmp;
            }
            then {
                policer policer-1m;
                accept;
            }
        }
        <additional terms>
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter <name> {
        term accept-tcp-initial {
            from {
                source-prefix-list {
                    management-networks-ipv6;
                }
                destination-prefix-list {
                    router-addresses-ipv6;
                }
                next-header tcp;
                destination-port ssh;
                tcp-initial;
            }
            then {
                policer policer-32k; << Lower rate for connection attempts to help prevent SYN flood attacks.
                accept;
            }
        }
        term accept-ssh {
            from {
                source-prefix-list {
                    management-networks-ipv6;
                }
                destination-prefix-list {
                    router-addresses-ipv6;
                }
                next-header tcp;
                destination-port ssh;
            }
            then {
                policer policer-1g; << Higher rate after connection establishment for remote management.
                accept;
            }
        }
        term accept-snmp {
            from {
                source-prefix-list {
                    snmp-servers-ipv6;
                }
                destination-prefix-list {
                    router-addresses-ipv6;
                }
                next-header udp;
                destination-port snmp;
            }
            then {
                policer policer-1m;
                accept;
            }
        }
        <additional terms>
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}

Note: Verify the applied filter has terms for all permitted traffic (e.g., OSPF, BGP, etc.).
policer policer-1g {
    if-exceeding {
        bandwidth-limit 1g;
        burst-size-limit 100k;
    }
    then discard;
}
policer policer-1m {
    if-exceeding {
        bandwidth-limit 1m;
        burst-size-limit 15k;
    }
    then discard;
}
policer policer-32k {
    if-exceeding {
        bandwidth-limit 32k;
        burst-size-limit 1500;
    }
    then discard;
}
[edit interfaces]
lo0 {
    unit <number> {
        family inet {
            filter {
                input <filter name>;
            }
            address <IPv4 address>/32;
        }
        family inet6 {
            filter {
                input <filter name>;
            }
            address <IPv6 address>/128/
        }
    }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router does not have control plane protection implemented, this is a finding.'
  desc 'fix', 'Implement control plane protection by classifying traffic types based on importance and configure filters to restrict and rate limit the traffic directed to and processed by the RE according to each class.

set firewall family inet filter <name> term accept-tcp-initial from source-prefix-list management-networks-ipv4
set firewall family inet filter <name> term accept-tcp-initial from destination-prefix-list router-addresses-ipv4
set firewall family inet filter <name> term accept-tcp-initial from protocol tcp
set firewall family inet filter <name> term accept-tcp-initial from destination-port ssh
set firewall family inet filter <name> term accept-tcp-initial from tcp-initial
set firewall family inet filter <name> term accept-tcp-initial then policer policer-32k
set firewall family inet filter <name> term accept-tcp-initial then accept
set firewall family inet filter <name> term accept-ssh from source-prefix-list management-networks-ipv4
set firewall family inet filter <name> term accept-ssh from destination-prefix-list router-addresses-ipv4
set firewall family inet filter <name> term accept-ssh from protocol tcp
set firewall family inet filter <name> term accept-ssh from destination-port ssh
set firewall family inet filter <name> term accept-ssh then policer policer-1g
set firewall family inet filter <name> term accept-ssh then count accept-ssh
set firewall family inet filter <name> term accept-ssh then accept
set firewall family inet filter <name> term accept-snmp from source-prefix-list snmp-servers-ipv4
set firewall family inet filter <name> term accept-snmp from destination-prefix-list router-addresses-ipv4
set firewall family inet filter <name> term accept-snmp from protocol udp
set firewall family inet filter <name> term accept-snmp from destination-port snmp
set firewall family inet filter <name> term accept-snmp then policer policer-1m
set firewall family inet filter <name> term accept-snmp then count accept-snmp
set firewall family inet filter <name> term accept-snmp then accept
<additional terms>
set firewall family inet filter <name> term default-deny then log
set firewall family inet filter <name> term default-deny then syslog
set firewall family inet filter <name> term default-deny then discard

set firewall policer policer-1g if-exceeding bandwidth-limit 1g
set firewall policer policer-1g burst-size-limit 100k
set firewall policer policer-1g then discard
set firewall policer policer-1m if-exceeding bandwidth-limit 1m
set firewall policer policer-1m burst-size-limit 15k
set firewall policer policer-1m then discard
set firewall policer policer-32k if-exceeding bandwidth-limit 132k
set firewall policer policer-32k burst-size-limit 1500
set firewall policer policer-32k then discard

set interfaces lo0 unit <number> family inet filter <name>
set interfaces lo0 unit <number> family inet address <IPv4 address>/32
set interfaces lo0 unit <number> family inet6 filter <name>
set interfaces lo0 unit <number> family inet6 address <IPv6 address>/128'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57483r844124_chk'
  tag severity: 'medium'
  tag gid: 'V-254031'
  tag rid: 'SV-254031r844126_rule'
  tag stig_id: 'JUEX-RT-000590'
  tag gtitle: 'SRG-NET-000362-RTR-000110'
  tag fix_id: 'F-57434r844125_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
