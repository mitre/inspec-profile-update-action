control 'SV-220517' do
  title 'The Cisco switch must be running an IOS release that is currently supported by Cisco Systems.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities. Running a supported release also enables operations to maintain a stable and reliable network provided by improved quality of service and security features.'
  desc 'check', 'Verify that the switch is in compliance with this requirement by having the switch administrator enter the following command: show version

Verify that the release is still supported by Cisco. All releases supported by Cisco can be found on the following URL:

www.cisco.com/c/en/us/support/ios-nx-os-software

If the switch is not running a supported release, this is a finding.'
  desc 'fix', 'Upgrade the switch to a supported release.'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22232r539272_chk'
  tag severity: 'high'
  tag gid: 'V-220517'
  tag rid: 'SV-220517r879887_rule'
  tag stig_id: 'CISC-ND-001470'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-22221r539273_fix'
  tag 'documentable'
  tag legacy: ['SV-110683', 'V-101579']
  tag cci: ['CCI-000366', 'CCI-002605']
  tag nist: ['CM-6 b', 'SI-2 c']
end
