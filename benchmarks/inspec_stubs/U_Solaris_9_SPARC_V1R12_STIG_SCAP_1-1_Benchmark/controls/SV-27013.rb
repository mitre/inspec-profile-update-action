control 'SV-27013' do
  title 'The /usr/aset/userlist file must be group-owned by root.'
  desc 'The /usr/aset/userlist file is critical to system security and must be protected from unauthorized access.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /usr/aset/userlist'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22600'
  tag rid: 'SV-27013r1_rule'
  tag stig_id: 'GEN000000-SOL00250'
  tag gtitle: 'GEN000000-SOL00250'
  tag fix_id: 'F-24278r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
