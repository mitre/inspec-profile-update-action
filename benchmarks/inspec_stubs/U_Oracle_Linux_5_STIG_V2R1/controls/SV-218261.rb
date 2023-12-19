control 'SV-218261' do
  title 'All files and directories must have a valid owner.'
  desc 'Un-owned files and directories may be unintentionally inherited if a user is assigned the same UID as the UID of the un-owned files.'
  desc 'check', 'Check the system for files with no assigned owner.

Procedure:
# find / -ignore_readdir_race -nouser

If any files have no assigned owner, this is a finding.

Caution should be used when centralized authorization is used because valid files may appear as unowned due to communication issues.'
  desc 'fix', "All directories and files (executable and data) will have an identifiable owner and group name. Either trace files to an authorized user, change the file's owner to root, or delete them. Determine the legitimate owner of the files and use the chown command to set the owner and group to the correct value. If the legitimate owner cannot be determined, change the owner to root (but make sure none of the changed files remain executable because they could be Trojan horses or other malicious code). Examine the files to determine their origin and the reason for their lack of an owner/group."
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19736r554120_chk'
  tag severity: 'medium'
  tag gid: 'V-218261'
  tag rid: 'SV-218261r603259_rule'
  tag stig_id: 'GEN001160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19734r554121_fix'
  tag 'documentable'
  tag legacy: ['V-785', 'SV-64463']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
