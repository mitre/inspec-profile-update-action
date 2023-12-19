control 'SV-218262' do
  title 'All files and directories must have a valid group-owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same GID as the GID of the files without a valid group-owner.'
  desc 'check', 'Search the system for files without a valid group-owner.
# find / -ignore_readdir_race -nogroup
If any files are found, this is a finding.'
  desc 'fix', 'Change the group-owner for each file without a valid group-owner.
# chgrp avalidgroup /tmp/a-file-without-a-valid-group-owner'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19737r554123_chk'
  tag severity: 'medium'
  tag gid: 'V-218262'
  tag rid: 'SV-218262r603259_rule'
  tag stig_id: 'GEN001170'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19735r554124_fix'
  tag 'documentable'
  tag legacy: ['V-22312', 'SV-64465']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
