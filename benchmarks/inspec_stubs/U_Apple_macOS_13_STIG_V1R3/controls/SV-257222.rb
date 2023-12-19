control 'SV-257222' do
  title "The macOS system must set permissions on user home directories to prevent users from having access to read or modify another user's files."
  desc 'Configuring the operating system to use the most restrictive permissions possible for user home directories helps to protect against inadvertent disclosures.

'
  desc 'check', %q(Verify the macOS system is configured so that permissions are set correctly on user home directories with the following commands:

/bin/ls -le /Users

This command will return a listing of the permissions of the root of every user account configured on the system. For each of the users, the permissions must be "drwxr-xr-x+", with the user listed as the owner and the group listed as "staff". The plus(+) sign indicates an associated Access Control List, which must be:
0: group:everyone deny delete

For every authorized user account, also run the following command:
/usr/bin/sudo /bin/ls -le /Users/userid, where userid is an existing user. 

This command will return the permissions of all the objects under the users' home directory. The permissions for each of the subdirectories must be:
drwx------+ 
 0: group:everyone deny delete

The exception is the "Public" directory, whose permissions must match the following:
drwxr-xr-x+ 
 0: group:everyone deny delete

If the permissions returned by either of these checks differ from what is shown, this is a finding.)
  desc 'fix', 'Configure the macOS system to set the appropriate permissions for each user on the system with the following command:

/usr/sbin/diskutil resetUserPermissions / DeviceNode UID, where "DeviceNode UID" is the ID number for the user whose home directory permissions need to be repaired.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60907r905297_chk'
  tag severity: 'medium'
  tag gid: 'V-257222'
  tag rid: 'SV-257222r905299_rule'
  tag stig_id: 'APPL-13-002068'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-60848r905298_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00228', 'SRG-OS-000480-GPOS-00230']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
