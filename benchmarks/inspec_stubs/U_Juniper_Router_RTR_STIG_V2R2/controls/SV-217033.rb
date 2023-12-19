control 'SV-217033' do
  title 'The Juniper perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.'
  desc "Enclaves with alternate gateway connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's alternate gateway, the perimeter router could be routing transit data from the Internet into the NIPRNet. This could also make the perimeter router vulnerable to a denial-of-service (DoS) attack as well as provide a back door into the NIPRNet. The DoD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an Approved Gateway is secure through filters permitting packets with a destination address belonging to the DoD enclave's address block."
  desc 'check', %q(This requirement is not applicable for the DoDIN Backbone.

Verify the interface connecting to ISP has an inbound filter as shown in the example below.

interfaces {
    ge-0/0/0 {
        description "Verizon ISP link";
        unit 0 {
            family inet {
                filter {
                    input ISP_FILTER;
                }
                address 11.1.12.2/24;
            }
        }
    }

Verify that the filter only allows traffic to specific destination addresses (i.e. enclave’s NIPRNet address space) as shown in the example below.

firewall {
    family inet {
        filter ISP_FILTER {
            term RESTRICT_DESTINATION {
                from {
                    destination-address {
                        0.0.0.0/0;
                        11.1.0.0/16 except;
                    }
                }
                then {
                    syslog;
                    discard;
                }
            }
            term ALLOW_XYZ {
                from {
                    protocol xyz;
                }
                then accept;
            }
            …
            …
            …
            term DENY_ALL_OTHER {
                then {
                    syslog;
                    reject;
                }
            }
        }

If the ingress filter bound to the interface connecting to an alternate gateway permits packets with addresses other than those specified, such as destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider, this is a finding.)
  desc 'fix', "This requirement is not applicable for the DoDIN Backbone.

Configure the ingress filter of the perimeter router connected to an alternate gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider as shown in the example below.

[edit firewall family inet filter ISP_FILTER]
set term RESTRICT_DESTINATION from destination-address 0.0.0.0/0
set term RESTRICT_DESTINATION from destination-address 11.1.0.0/16 except
set term RESTRICT_DESTINATION then syslog discard
insert term RESTRICT_DESTINATION before term ALLOW_XYZ"
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18262r296967_chk'
  tag severity: 'high'
  tag gid: 'V-217033'
  tag rid: 'SV-217033r639663_rule'
  tag stig_id: 'JUNI-RT-000280'
  tag gtitle: 'SRG-NET-000019-RTR-000008'
  tag fix_id: 'F-18260r296968_fix'
  tag 'documentable'
  tag legacy: ['V-90851', 'SV-101061']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
