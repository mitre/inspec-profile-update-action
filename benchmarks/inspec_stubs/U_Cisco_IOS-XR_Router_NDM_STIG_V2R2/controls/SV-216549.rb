control 'SV-216549' do
  title 'The Cisco router must be running an IOS release that is currently supported by Cisco Systems.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities. Running a supported release also enables operations to maintain a stable and reliable network provided by improved quality of service and security features.'
  desc 'check', 'Verify that the router is in compliance with this requirement by having the router administrator enter the following command: show version

Verify that the release is still supported by Cisco. All releases supported by Cisco can be found on the following URL:

www.cisco.com/c/en/us/support/ios-nx-os-software

If the router is not running a supported release, this is a finding.'
  desc 'fix', 'Upgrade the router to a supported release.'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17784r288333_chk'
  tag severity: 'high'
  tag gid: 'V-216549'
  tag rid: 'SV-216549r531088_rule'
  tag stig_id: 'CISC-ND-001470'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-17781r288334_fix'
  tag 'documentable'
  tag legacy: ['SV-105639', 'V-96501']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
