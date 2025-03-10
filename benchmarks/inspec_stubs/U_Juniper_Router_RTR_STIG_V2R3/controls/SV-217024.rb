control 'SV-217024' do
  title 'The Juniper router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if it has been configured to ensure the router does not send ICMP Redirect messages out to any external interface.

interfaces {
    ge-1/0/0 {
        unit 0 {
            family inet {
                no-redirects;
                address 11.1.12.2/24;
            }
        }
    }
    ge-1/1/0  {
        unit 0 {
            family inet {
                no-redirects;
                address 11.1.23.2/24;
            }
        }
    }

If ICMP Redirect messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP redirects on all external interfaces as shown in the example below.

[edit interfaces]
set ge-1/0/0 unit 0 family inet no-redirects
set ge-1/1/0 unit 0 family inet no-redirects'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18253r296940_chk'
  tag severity: 'medium'
  tag gid: 'V-217024'
  tag rid: 'SV-217024r604135_rule'
  tag stig_id: 'JUNI-RT-000190'
  tag gtitle: 'SRG-NET-000362-RTR-000115'
  tag fix_id: 'F-18251r296941_fix'
  tag 'documentable'
  tag legacy: ['SV-101043', 'V-90833']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
