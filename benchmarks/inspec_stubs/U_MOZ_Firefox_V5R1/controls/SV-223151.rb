control 'SV-223151' do
  title 'Installed version of Firefox unsupported.'
  desc 'Use of versions of an application which are not supported by the vendor are not permitted. Vendors respond to security flaws with updates and patches. These updates are not available for unsupported version which can leave the application vulnerable to attack.'
  desc 'check', 'Method 1: View the following registry key: 
HKLM\\Software\\Mozilla\\Mozilla Firefox\\CurrentVersion

Method 2: Run Firefox. Click the ellipsis button >> Help >> About Firefox, and view the version number.

Criteria: If the Firefox version is not a supported version, this is a finding.'
  desc 'fix', 'Upgrade the version of the browser to an approved version by obtaining software from the vendor or other trusted source.'
  impact 0.7
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24824r531270_chk'
  tag severity: 'high'
  tag gid: 'V-223151'
  tag rid: 'SV-223151r612236_rule'
  tag stig_id: 'DTBF003'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24812r531271_fix'
  tag 'documentable'
  tag legacy: ['SV-19509', 'V-17988']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
