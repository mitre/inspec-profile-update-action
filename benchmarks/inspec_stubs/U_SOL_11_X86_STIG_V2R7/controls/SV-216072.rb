control 'SV-216072' do
  title 'System start-up files must only execute programs owned by a privileged UID or an application.'
  desc 'System start-up files executing programs owned by other than root (or another privileged user) or an application indicates the system may have been compromised.'
  desc 'check', 'Determine the programs executed by system start-up files.  Determine the ownership of the executed programs. 

# cat /etc/rc* /etc/init.d/* | more

Check the ownership of every program executed by the system start-up files.

# ls -l <executed program>

If any executed program is not owned by root, sys, bin, or in rare cases, an application account, this is a finding.'
  desc 'fix', 'Change the ownership of the file executed from system startup scripts to root, bin, or sys.

# chown root <executed file>'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17310r372598_chk'
  tag severity: 'medium'
  tag gid: 'V-216072'
  tag rid: 'SV-216072r603268_rule'
  tag stig_id: 'SOL-11.1-020380'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17308r372599_fix'
  tag 'documentable'
  tag legacy: ['V-59843', 'SV-74273']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
