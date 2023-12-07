control 'SV-38942' do
  title 'All files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same UID as the UID of the unowned files.'
  desc 'check', 'Check the system for files with no assigned owner.

Procedure:
# find / -nouser -print

If any files have no assigned owner, this is a finding.'
  desc 'fix', "All directories and files (executable and data) will have an identifiable owner and group name. Either trace files to an authorized user, change the file's owner to root, or delete them. Determine the legitimate owner of the files and use the chown command to set the owner and group to the correct value. If the legitimate owner cannot be determined, change the owner to root (but make sure none of the changed files remain executable because they could be Trojan horses or other malicious code). Examine the files to determine their origin and the reason for their lack of an owner/group.  
#chown <a-valid-user> <directory>/<file>"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-290r2_chk'
  tag severity: 'medium'
  tag gid: 'V-785'
  tag rid: 'SV-38942r1_rule'
  tag stig_id: 'GEN001160'
  tag gtitle: 'GEN001160'
  tag fix_id: 'F-32206r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
