control 'SV-37161' do
  title 'All files and directories must have a valid owner.'
  desc 'Un-owned files and directories may be unintentionally inherited if a user is assigned the same UID as the UID of the un-owned files.'
  desc 'check', 'Check the system for files with no assigned owner.

Procedure:
# find / -ignore_readdir_race -nouser 

If any files have no assigned owner, this is a finding.

Caution should be used when centralized authorization is used because valid files may appear as unowned due to communication issues.'
  desc 'fix', "All directories and files (executable and data) will have an identifiable owner and group name. Either trace files to an authorized user, change the file's owner to root, or delete them. Determine the legitimate owner of the files and use the chown command to set the owner and group to the correct value. If the legitimate owner cannot be determined, change the owner to root (but make sure none of the changed files remain executable because they could be Trojan horses or other malicious code). Examine the files to determine their origin and the reason for their lack of an owner/group."
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35868r2_chk'
  tag severity: 'medium'
  tag gid: 'V-785'
  tag rid: 'SV-37161r2_rule'
  tag stig_id: 'GEN001160'
  tag gtitle: 'GEN001160'
  tag fix_id: 'F-31123r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
