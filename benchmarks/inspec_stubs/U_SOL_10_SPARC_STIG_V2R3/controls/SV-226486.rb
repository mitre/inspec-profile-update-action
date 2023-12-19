control 'SV-226486' do
  title 'All files and directories must have a valid group-owner.'
  desc 'Files without a valid group-owner may be unintentionally inherited if a group is assigned the same GID as the GID of the files without a valid group-owner.'
  desc 'check', 'Search the system for files without a valid group-owner.
# find / -nogroup -print
If any files are found, this is a finding.'
  desc 'fix', 'Change the group owner for each file without a valid group owner.
# chgrp <a-valid-group> /tmp/a-file-without-a-valid-group-owner'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28647r482843_chk'
  tag severity: 'medium'
  tag gid: 'V-226486'
  tag rid: 'SV-226486r603265_rule'
  tag stig_id: 'GEN001170'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28635r482844_fix'
  tag 'documentable'
  tag legacy: ['V-22312', 'SV-26358']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
