control 'SV-248636' do
  title 'All OL 8 world-writable directories must be owned by root, sys, bin, or an application user.'
  desc 'If a world-writable directory is not owned by root, sys, bin, or an application User Identifier (UID), unauthorized users may be able to modify files created by others. 
 
The only authorized public directories are the temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'The following command will discover and print world-writable directories that are not owned by a system account, given the assumption that only system accounts have a UID lower than 1000. Run it once for each local partition [PART]: 
 
$ sudo find [PART] -xdev -type d -perm -0002 -uid +999 -print 
 
If there is output, this is a finding.'
  desc 'fix', 'Investigate any world-writable directories that are not owned by a system account and then delete the files or assign them to an appropriate group.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52070r779472_chk'
  tag severity: 'medium'
  tag gid: 'V-248636'
  tag rid: 'SV-248636r779474_rule'
  tag stig_id: 'OL08-00-010700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52024r779473_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
