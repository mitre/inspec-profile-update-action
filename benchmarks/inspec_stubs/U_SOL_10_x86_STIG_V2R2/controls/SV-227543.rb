control 'SV-227543' do
  title 'The /usr/aset/userlist file must be group-owned by root.'
  desc 'The /usr/aset/userlist file is critical to system security and must be protected from unauthorized access.'
  desc 'check', 'Check the group ownership of the file.
# ls -lLd /usr/aset/userlist
If the group owner of the file is not root, this is a finding.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /usr/aset/userlist'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29705r488162_chk'
  tag severity: 'medium'
  tag gid: 'V-227543'
  tag rid: 'SV-227543r603266_rule'
  tag stig_id: 'GEN000000-SOL00250'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29693r488163_fix'
  tag 'documentable'
  tag legacy: ['SV-27013', 'V-22600']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
