control 'SV-37165' do
  title 'All files and directories must have a valid group-owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same GID as the GID of the files without a valid group-owner.'
  desc 'check', 'Search the system for files without a valid group-owner.
# find / -ignore_readdir_race -nogroup 
If any files are found, this is a finding.'
  desc 'fix', 'Change the group-owner for each file without a valid group-owner.
# chgrp avalidgroup /tmp/a-file-without-a-valid-group-owner'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35872r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22312'
  tag rid: 'SV-37165r2_rule'
  tag stig_id: 'GEN001170'
  tag gtitle: 'GEN001170'
  tag fix_id: 'F-31126r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
