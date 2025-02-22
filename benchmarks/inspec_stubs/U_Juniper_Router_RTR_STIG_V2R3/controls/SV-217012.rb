control 'SV-217012' do
  title 'The Juniper router must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration. Verify that neighbor router authentication is enabled for all routing protocols as shown in the example configuration below.

protocols {
    bgp {
        group AS_5 {
            type external;
            peer-as 5;
            neighbor x.x.x.x {
                authentication-key "$8$tBga0ORx7VsYoIEgJ"; ## SECRET-DATA
            }
        }
    }
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                authentication {
                    simple-password "$8$NHVb2mPQ3nCYg/t"; ## SECRET-DATA
                }
            }
            interface ge-0/1/0.0 {
                authentication {
                    simple-password "$8$Lgb7NbHkPTQnVwF/"; ## SECRET-DATA
                }
            }
            interface lo0.0;
            interface ge-0/2/0.0 {
                authentication {
                    simple-password "$8$7DdVY.mTF39s26A"; ## SECRET-DATA
                }
            }
        }
    }
   isis {
        level 1 {
            authentication-key "$8$n2OT9CuvMXN-wp0VY"; ## SECRET-DATA
            authentication-type md5;
        }
        level 2 {
            authentication-key "$8$8G9x7ViHm5T3dbz6"; ## SECRET-DATA
            authentication-type md5;
        }
        interface ge-0/0/0.0;
        interface ge-0/0/1.0;
    }
    ldp {
        interface ge-0/0/0.0;
        interface ge-0/0/1.0;
        session 10.3.3.3 {
            authentication-key "$8$3hus/u1ylMNVYX7qf"; ## SECRET-DATA
        }
        session 10.1.2.2 {
            authentication-key "$8$Qq0I3nCrlMLX-9A7V"; ## SECRET-DATA
        }
    }
    rip {
        authentication-type md5;
        authentication-key "$8$34fM/u1ylMNVYX7qf"; ## SECRET-DATA
        group RIP_GROUP {
                 neighbor ge-1/0/1.0;
        }
    }
}

If authentication is not enabled for all control plane protocols, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for all control plane protocols as shown in the example below.

[edit protocols ospf area 0.0.0.0]
set interface ge-0/0/0 authentication simple-password xxxxxxxxxxxx
set interface ge-0/1/0 authentication simple-password xxxxxxxxxxxx
set interface ge-0/2/0 authentication simple-password xxxxxxxxxxxx

[edit protocols isis]
set level 1 authentication-type md5
set level 1 authentication-key xxxxxxxx
set level 2 authentication-type md5
set level 2 authentication-key xxxxxxxx

[edit protocols rip]
set authentication-type md5
set authentication-key xxxxxxxx

[edit protocols bgp group AS_2 neighbor x.x.x.x]
set authentication-key xxxxxxxxxxxxxxx

[edit protocols ldp]
set session 10.1.2.2 authentication-key xxxxxxxxxx'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18241r296904_chk'
  tag severity: 'medium'
  tag gid: 'V-217012'
  tag rid: 'SV-217012r604135_rule'
  tag stig_id: 'JUNI-RT-000020'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-18239r296905_fix'
  tag 'documentable'
  tag legacy: ['SV-101019', 'V-90809']
  tag cci: ['CCI-002205', 'CCI-000366']
  tag nist: ['AC-4 (17)', 'CM-6 b']
end
