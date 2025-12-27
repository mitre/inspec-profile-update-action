control 'SV-220140' do
  title 'The Cisco router must be running an IOS release that is currently supported by Cisco Systems.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities. Running a supported release also enables operations to maintain a stable and reliable network provided by improved quality of service and security features.'
  desc 'check', 'Verify that the router is in compliance with this requirement by having the router administrator enter the following command: 

show version

Verify that the release is still supported by Cisco. All releases supported by Cisco can be found on the following URL:

www.cisco.com/c/en/us/support/ios-nx-os-software

If the router is not running a supported release, this is a finding.'
  desc 'fix', 'Upgrade the router to a supported release.'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-21855r388870_chk'
  tag severity: 'high'
  tag gid: 'V-220140'
  tag rid: 'SV-220140r531083_rule'
  tag stig_id: 'CISC-ND-001470'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-21847r388871_fix'
  tag 'documentable'
  tag legacy: ['SV-105507', 'V-96369']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
