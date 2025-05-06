control 'SV-220034' do
  title 'Global initialization files must contain the mesg -n or mesg n commands.'
  desc 'If the mesg -n or mesg n command is not placed into the system profile, messaging can be used to cause a Denial of Service attack.'
  desc 'check', 'Check global initialization files for the presence of "mesg -n" or "mesg n".

Procedure:
# grep mesg /etc/.login /etc/profile /etc/bashrc /etc/environment /etc/security/environ /etc/csh.login /etc/csh.cshrc

If no existing global initialization files contain "mesg -n" or "mesg n", this is a finding.'
  desc 'fix', 'Edit /etc/profile or another global initialization script and add the mesg -n command.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21743r483041_chk'
  tag severity: 'low'
  tag gid: 'V-220034'
  tag rid: 'SV-220034r603265_rule'
  tag stig_id: 'GEN001780'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21742r483042_fix'
  tag 'documentable'
  tag legacy: ['V-825', 'SV-39828']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
