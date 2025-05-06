control 'SV-254036' do
  title 'The Juniper router must be configured to have Internet Control Message Protocol (ICMP) redirects disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if controls have been defined to ensure the router does not send ICMP Redirect messages out to any external interfaces.

Verify the global "no-redirects" statement is enabled under [edit system] or that individual interface "no-redirects" statements are configured on external interfaces.
[edit system]
no-redirects;
[edit interfaces]
<external interface name> {
    unit <number> {
        family inet {
            no-redirects;
            address <IPv4 address>.<mask>;
        }
        family inet6 {
            no-redirects;
            address <IPv6 address>.<prefix>;
        }
    }
}

If ICMP Redirect messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP redirects on all external interfaces.

set system no-redirects

set interfaces <external interface name> unit <number> family inet no-redirects
set interfaces <external interface name> unit <number> family inet6 no-redirects'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57488r844139_chk'
  tag severity: 'medium'
  tag gid: 'V-254036'
  tag rid: 'SV-254036r844141_rule'
  tag stig_id: 'JUEX-RT-000640'
  tag gtitle: 'SRG-NET-000362-RTR-000115'
  tag fix_id: 'F-57439r844140_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
