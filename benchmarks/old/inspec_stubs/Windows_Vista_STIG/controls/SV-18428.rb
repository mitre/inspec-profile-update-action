control 'SV-18428' do
  title 'User Account Control – Executable Elevation'
  desc 'This check verifies that elevation of application in UAC is not restricted to signed and validated applications per the FDCC.'
  desc 'fix', 'Configure the setting for “User Account Control: Only elevate executables that are signed and validated” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-17374'
  tag rid: 'SV-18428r2_rule'
  tag gtitle: 'UAC – Executable Elevation'
  tag fix_id: 'F-17280r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
