control 'SV-216070' do
  title 'All system start-up files must be owned by root.'
  desc 'System start-up files not owned by root could lead to system compromise by allowing malicious users or applications to modify them for unauthorized purposes.  This could lead to system and network compromise.'
  desc 'check', "Check run control scripts' ownership.

# ls -lL /etc/rc* /etc/init.d

If any run control script is not owned by root, this is a finding."
  desc 'fix', 'Change the ownership of the run control script(s) with incorrect ownership.

# chown root <run control script>'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17308r372592_chk'
  tag severity: 'medium'
  tag gid: 'V-216070'
  tag rid: 'SV-216070r603268_rule'
  tag stig_id: 'SOL-11.1-020360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17306r372593_fix'
  tag 'documentable'
  tag legacy: ['V-59839', 'SV-74269']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
