control 'SV-218277' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are critical to system security.  Unauthorized modification of these files could compromise these processes and the system."
  desc 'check', "Perform the following to check NIS file permissions.

# ls -la /var/yp/*

If the file's mode is more permissive than 0755, this is a finding."
  desc 'fix', 'Change the mode of NIS/NIS+/yp command files to 0755 or less permissive.

Procedure (example):
# chmod 0755 <filename>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19752r561620_chk'
  tag severity: 'medium'
  tag gid: 'V-218277'
  tag rid: 'SV-218277r603259_rule'
  tag stig_id: 'GEN001360'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19750r561621_fix'
  tag 'documentable'
  tag legacy: ['V-791', 'SV-64509']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
