control 'SV-220621' do
  title 'The Cisco switch must be running an IOS release that is currently supported by Cisco Systems.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities. Running a supported release enables operations to maintain a stable and reliable network provided by improved quality of service and security features.'
  desc 'check', 'Verify that the switch is in compliance with this requirement by having the switch administrator enter the following command: 

show version

Verify that the release is still supported by Cisco. All releases supported by Cisco can be found at:

www.cisco.com/c/en/us/support/ios-nx-os-software

If the switch is not running a supported release, this is a finding.'
  desc 'fix', 'Upgrade the switch to a supported release.'
  impact 0.7
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22336r507909_chk'
  tag severity: 'high'
  tag gid: 'V-220621'
  tag rid: 'SV-220621r879887_rule'
  tag stig_id: 'CISC-ND-001470'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-22325r507910_fix'
  tag 'documentable'
  tag legacy: ['SV-110471', 'V-101367']
  tag cci: ['CCI-002605', 'CCI-000366']
  tag nist: ['SI-2 c', 'CM-6 b']
end
