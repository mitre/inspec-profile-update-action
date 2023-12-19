control 'SV-14850' do
  title 'User Account Control - Elevate UIAccess applications that are in secure locations'
  desc 'This check verifies whether Windows only allows applications installed in a secure location, such as the Program Files or the Windows\\System32 folders, on the file system to run with elevated privileges.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Only elevate UIAccess applications that are installed in secure locations” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14239'
  tag rid: 'SV-14850r1_rule'
  tag gtitle: 'UAC - UIAccess Application Elevation'
  tag fix_id: 'F-28845r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
