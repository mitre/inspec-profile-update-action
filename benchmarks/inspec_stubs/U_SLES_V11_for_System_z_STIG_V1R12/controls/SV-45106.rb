control 'SV-45106' do
  title 'Global initialization files must contain the mesg -n or mesg n commands.'
  desc 'If the "mesg -n" or "mesg n" command is not placed into the system profile, messaging can be used to cause a Denial of Service attack.'
  desc 'check', 'Check global initialization files for the presence of "mesg -n" or "mesg n".

Procedure:
# grep "mesg" /etc/bash.bashrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/ksh.kshrc /etc/profile /etc/profile.d/* /etc/zshrc

If no global initialization files contain "mesg -n" or "mesg n", this is a finding.'
  desc 'fix', 'Edit /etc/profile or another global initialization script, and add the "mesg -n" command.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42463r1_chk'
  tag severity: 'low'
  tag gid: 'V-825'
  tag rid: 'SV-45106r1_rule'
  tag stig_id: 'GEN001780'
  tag gtitle: 'GEN001780'
  tag fix_id: 'F-38505r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
