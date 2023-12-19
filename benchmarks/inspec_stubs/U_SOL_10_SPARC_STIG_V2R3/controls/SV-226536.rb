control 'SV-226536' do
  title 'All run control scripts must have mode 0755 or less permissive.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', 'Check run control script modes.

# ls -lL /etc/rc* /etc/init.d /lib/svc/method

If any run control script has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Ensure all system startup files have mode 0755 or less permissive. Examine the rc files, and all files in the rc1.d (rc2.d, and so on) directories, and in the /etc/init.d and /lib/svc/method directories to ensure they are not world-writable. If they are world-writable, use the chmod command to correct the vulnerability and to research why.

Procedure: 
# chmod go-w <startupfile>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36387r602764_chk'
  tag severity: 'medium'
  tag gid: 'V-226536'
  tag rid: 'SV-226536r603265_rule'
  tag stig_id: 'GEN001580'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36351r602765_fix'
  tag 'documentable'
  tag legacy: ['SV-27199', 'V-906']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
