control 'SV-217011' do
  title 'The Juniper router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that firewall filters are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. For example, the configuration below will allow only printer traffic into subnet 11.1.23.0/24 and SQL traffic into subnet 11.1.24.0/24. ICMP is allowed for troubleshooting and OSPF is the routing protocol used within the network.

interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter {
                    input FILTER_SERVER_TRAFFIC;
                }
                address 11.1.12.2/24;
            }
        }
    }
…
…
…
firewall {
    family inet {
        filter FILTER_SERVER_TRAFFIC {
            term PRINT_FILTER {
                from {
                    destination-address {
                        11.1.23.0/24;
                    }
                    protocol tcp;
                    destination-port [ 515 631 9100 ];
                }
                then accept;
            }
            term SQL_FILTER {
                from {
                    destination-address {
                        11.1.24.0/24;
                    }
                    protocol tcp;
                    destination-port [ 1433 1434 4022 ];
                }
                then accept;
            }
            term ALLOW_OSPF {
                from {
                    protocol ospf;
                }
                then accept;
            }
            term ALLOW_ICMP {
                from {
                    protocol icmp;
                }
                then accept;
            }
            term DENY_ALL_OTHER {
                then {
                    log;
                    syslog;
                    reject;
                }
            }
        }



If the router is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure firewall filters to allow or deny traffic for specific source and destination addresses as well as ports and protocols between various subnets as required. The commands used below were used to create the configuration as shown in the check content.

[edit firewall family inet]
set filter FILTER_SERVER_TRAFFIC term PRINT_FILTER from destination-address 11.1.23.0/24
set filter FILTER_SERVER_TRAFFIC term PRINT_FILTER from protocol tcp destination-port [515 631 9100] 
set filter FILTER_SERVER_TRAFFIC term PRINT_FILTER then accept
set filter FILTER_SERVER_TRAFFIC term SQL_FILTER from destination-address 11.1.24.0/24
set filter FILTER_SERVER_TRAFFIC term SQL_FILTER from protocol tcp destination-port [1433 1434 4022]
set filter FILTER_SERVER_TRAFFIC term SQL_FILTER then accept
set filter FILTER_SERVER_TRAFFIC term ALLOW_OSPF from protocol ospf
set filter FILTER_SERVER_TRAFFIC term ALLOW_OSPF then accept
set filter FILTER_SERVER_TRAFFIC term ALLOW_ICMP from protocol icmp
set filter FILTER_SERVER_TRAFFIC term ALLOW_ICMP then accept
set filter FILTER_SERVER_TRAFFIC term DENY_ALL_OTHER then log reject

[edit interfaces ge-0/0/0 unit 0 family inet]
set filter input FILTER_SERVER_TRAFFIC'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18240r296901_chk'
  tag severity: 'medium'
  tag gid: 'V-217011'
  tag rid: 'SV-217011r604135_rule'
  tag stig_id: 'JUNI-RT-000010'
  tag gtitle: 'SRG-NET-000018-RTR-000001'
  tag fix_id: 'F-18238r296902_fix'
  tag 'documentable'
  tag legacy: ['SV-101017', 'V-90807']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
