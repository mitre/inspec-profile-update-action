control 'SV-45043' do
  title 'All run control scripts must have mode 0755 or less permissive.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', 'Check run control script modes.
–
# ls -lL /etc/rc* /etc/init.d
If any run control script has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Ensure all system startup files have mode 0755 or less permissive. Examine the "rc" files, and all files in the rc1.d (rc2.d, and so on) directories, and in the /etc/init.d directory to ensure they are not world-writable. If they are world-writable, use the chmod command to correct the vulnerability and research why they are world-writable.

Procedure: 
# chmod 755 <startup file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42424r1_chk'
  tag severity: 'medium'
  tag gid: 'V-906'
  tag rid: 'SV-45043r1_rule'
  tag stig_id: 'GEN001580'
  tag gtitle: 'GEN001580'
  tag fix_id: 'F-38454r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
