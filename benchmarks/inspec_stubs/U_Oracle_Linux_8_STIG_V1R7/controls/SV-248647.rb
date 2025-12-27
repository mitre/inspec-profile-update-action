control 'SV-248647' do
  title 'All OL 8 files and directories must have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.'
  desc 'check', 'Verify all files and directories on OL 8 have a valid group with the following command: 
 
$ sudo find / -nogroup 
 
If any files on the system do not have an assigned group, this is a finding.'
  desc 'fix', 'Either remove all files and directories from OL 8 that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command: 
 
$ sudo chgrp <group> <file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52081r779505_chk'
  tag severity: 'medium'
  tag gid: 'V-248647'
  tag rid: 'SV-248647r779507_rule'
  tag stig_id: 'OL08-00-010790'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52035r779506_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
