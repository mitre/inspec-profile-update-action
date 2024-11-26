control 'SV-215340' do
  title 'All AIX files and directories must have a valid owner.'
  desc 'Unowned files do not directly imply a security problem, but they are generally a sign that something is amiss. They may be caused by an intruder, by incorrect software installation or draft software removal, or by failure to remove all files belonging to a deleted account. The files should be repaired so they will not cause problems when accounts are created in the future, and the cause should be discovered and addressed.'
  desc 'check', 'Check the system for files with no assigned owner using the following command:
# find / -nouser -print 

If any files have no assigned owner, this is a finding.'
  desc 'fix', %q(All directories and files (executable and data) will have an identifiable owner and group name. Either trace files to an authorized user, change the file's owner to "root", or delete them. Determine the legitimate owner of the files and use the "chown" command to set the owner and group to the correct value. If the legitimate owner cannot be determined, change the owner to "root" (but make sure none of the changed files remain executable because they could be trojan horses or other malicious code). Examine the files to determine their origin and the reason for their lack of an owner/group. 

From the command prompt, run the following command to set the owner and/or group on a file:
# chown <a-valid-user>.<a-valid-group> <directory>/<file>)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16538r294471_chk'
  tag severity: 'medium'
  tag gid: 'V-215340'
  tag rid: 'SV-215340r508663_rule'
  tag stig_id: 'AIX7-00-003034'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16536r294472_fix'
  tag 'documentable'
  tag legacy: ['SV-101725', 'V-91627']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
