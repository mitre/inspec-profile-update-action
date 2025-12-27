control 'SV-214225' do
  title 'The DHCP service must not be enabled on an external authoritative name server.'
  desc 'The site DNS and DHCP architecture must be reviewed to ensure only the appropriate services are enabled on each Grid Member. An external authoritative name server must be configured to allow only authoritative DNS.'
  desc 'check', 'Navigate to Grid >> Grid Manager >> Services tab.

Select "DHCP" and verify only internal Infoblox members have the service enabled.

If an external authoritative name server has DHCP enabled this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DHCP >> Members/Servers tab.

Select the Infoblox member using the check box and click "Stop" in the toolbar to disable the "DHCP" service.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15440r295938_chk'
  tag severity: 'medium'
  tag gid: 'V-214225'
  tag rid: 'SV-214225r612370_rule'
  tag stig_id: 'IDNS-7X-001000'
  tag gtitle: 'SRG-APP-000142-DNS-000014'
  tag fix_id: 'F-15438r295939_fix'
  tag 'documentable'
  tag legacy: ['V-68621', 'SV-83111']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
