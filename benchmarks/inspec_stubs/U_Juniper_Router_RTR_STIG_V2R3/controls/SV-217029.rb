control 'SV-217029' do
  title 'The Juniper perimeter router must be configured to deny network traffic by default and allow network traffic by exception.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic must be denied by default. Firewalls and perimeter routers should only allow traffic through that is explicitly permitted. The initial defense for the internal network is to block any traffic at the perimeter that is attempting to make a connection to a host residing on the internal network. In addition, allowing unknown or undesirable outbound traffic by the firewall or router will establish a state that will permit the return of this undesirable traffic inbound.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that the inbound filter applied to all external interfaces is configured to allow specific ports and protocols and deny all other traffic.

Verify that an inbound filter is applied to all external interfaces as shown in the example below.

interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter {
                    input FILTER_INBOUND_TRAFFIC;
                }
                address 11.1.12.2/24;
            }
        }
    }

Review inbound filters to verify that the ending term is configured to deny all other traffic that is not explicitly allowed.

firewall {
    family inet {
        filter FILTER_INBOUND_TRAFFIC {
            term ALLOW_BGP {
                from {
                    destination-address {
                        11.1.24.0/24;
                    }
                    protocol tcp;
                    destination-port bgp;
                }
                then accept;
            }
            …
            …
            …
            term ALLOW_XYZ {
                from {
                    protocol xyz;
                }
                then accept;
            }
            term DENY_ALL_OTHER {
                then {
                    syslog;
                    discard;
                }
            }
        }

If the filter is not configured to allow specific ports and protocols and deny all other traffic, this is a finding.

If the filter is not configured inbound on all external interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure a term at the end of the inbound filter to deny all other traffic by default as shown in the example below.

[edit firewall family inet]
set filter FILTER_INBOUND_TRAFFIC term DENY_ALL_OTHER then syslog discard'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18258r296955_chk'
  tag severity: 'high'
  tag gid: 'V-217029'
  tag rid: 'SV-217029r604135_rule'
  tag stig_id: 'JUNI-RT-000240'
  tag gtitle: 'SRG-NET-000202-RTR-000001'
  tag fix_id: 'F-18256r296956_fix'
  tag 'documentable'
  tag legacy: ['SV-101053', 'V-90843']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
