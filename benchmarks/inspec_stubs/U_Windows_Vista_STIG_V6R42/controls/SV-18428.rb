control 'SV-18428' do
  title 'User Account Control – Executable Elevation'
  desc 'This check verifies that elevation of application in UAC is not restricted to signed and validated applications per the FDCC.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view.  Navigate to Local Policies -> Security Options. If the value for “User Account Control: Only elevate executables that are signed and validated” is not set to “Disabled”, then this is a finding.'
  desc 'fix', 'Configure the setting for “User Account Control: Only elevate executables that are signed and validated” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-18083r1_chk'
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
