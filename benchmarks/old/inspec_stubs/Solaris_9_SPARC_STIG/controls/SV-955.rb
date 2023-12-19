control 'SV-955' do
  title 'The /usr/aset/userlist file must exist.'
  desc 'If the userlist file does not exist, then an unauthorized user may exist in the /etc/passwd file.'
  desc 'fix', 'Create the /usr/aset/userlist file and populate it with a list of authorized users.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-955'
  tag rid: 'SV-955r2_rule'
  tag stig_id: 'GEN000000-SOL00220'
  tag gtitle: 'GEN000000-SOL00220'
  tag fix_id: 'F-1109r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032', 'CCI-000366']
  tag nist: ['AC-4 (8) (a)', 'CM-6 b']
end
