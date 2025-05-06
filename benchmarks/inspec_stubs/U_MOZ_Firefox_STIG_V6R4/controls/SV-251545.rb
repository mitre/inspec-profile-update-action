control 'SV-251545' do
  title 'The installed version of Firefox must be supported.'
  desc 'Using versions of an application that are not supported by the vendor is not permitted. Vendors respond to security flaws with updates and patches. These updates are not available for unsupported versions, which can leave the application vulnerable to attack.'
  desc 'check', 'Run Firefox. Click the ellipsis button >> Help >> About Firefox, and view the version number.

If the Firefox version is not a supported version, this is a finding.'
  desc 'fix', 'Upgrade the version of the browser to an approved version by obtaining software from the vendor or other trusted source.'
  impact 0.7
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54980r807105_chk'
  tag severity: 'high'
  tag gid: 'V-251545'
  tag rid: 'SV-251545r849960_rule'
  tag stig_id: 'FFOX-00-000001'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-54934r807106_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
