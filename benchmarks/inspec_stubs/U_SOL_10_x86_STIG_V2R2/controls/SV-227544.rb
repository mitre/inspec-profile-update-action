control 'SV-227544' do
  title 'The /usr/aset/userlist file must have mode 0600 or less permissive.'
  desc 'A permission mask not set to the required level could allow unauthorized access to sensitive system files and resources.'
  desc 'check', '# ls -lL /usr/aset/userlist

If /usr/aset/userlist has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the /usr/aset/userlist file to 0600.
# chmod 0600 /usr/aset/userlist'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29706r488165_chk'
  tag severity: 'medium'
  tag gid: 'V-227544'
  tag rid: 'SV-227544r603266_rule'
  tag stig_id: 'GEN000000-SOL00260'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29694r488166_fix'
  tag 'documentable'
  tag legacy: ['SV-957', 'V-957']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
