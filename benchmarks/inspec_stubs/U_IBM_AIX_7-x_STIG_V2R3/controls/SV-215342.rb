control 'SV-215342' do
  title 'The AIX global initialization files must contain the mesg -n or mesg n commands.'
  desc 'Command "mesg -n" allows only the root user the permission to send messages to your workstation to avoid having others clutter your display with incoming messages.'
  desc 'check', 'Check global initialization files for the presence of "mesg n" command by running: 

# grep "mesg" /etc/profile /etc/environment /etc/security/environ /etc/security/.profile /etc/csh.login /etc/csh.cshrc 
/etc/profile:mesg n
/etc/environment:mesg n

If any global initialization file does not contain "mesg n", or it contains the "mesg y" command, this is a finding.'
  desc 'fix', 'Edit the global initialization files that do not contain "mesg n" command and add the following line to the initialization files:
mesg n'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16540r294477_chk'
  tag severity: 'medium'
  tag gid: 'V-215342'
  tag rid: 'SV-215342r508663_rule'
  tag stig_id: 'AIX7-00-003036'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16538r294478_fix'
  tag 'documentable'
  tag legacy: ['V-91631', 'SV-101729']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
