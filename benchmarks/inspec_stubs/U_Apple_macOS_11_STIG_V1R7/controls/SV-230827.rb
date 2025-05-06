control 'SV-230827' do
  title "The macOS system must set permissions on user home directories to prevent users from having access to read or modify another user's files."
  desc 'Configuring the operating system to use the most restrictive permissions possible for user home directories helps to protect against inadvertent disclosures.

'
  desc 'check', %q(To verify that permissions are set correctly on user home directories, use the following commands:

ls -le /Users

Should return a listing of the permissions of the  root of every user account configured on the system. For each of the users, the permissions should be:
"drwxr-xr-x+" with the user listed as the owner and the group listed as "staff". The plus(+) sign indicates an associated Access Control List, which should be:
 0: group:everyone deny delete

For every authorized user account, also run the following command:
/usr/bin/sudo ls -le /Users/userid, where userid is an existing user. 

This command will return the permissions of all of the objects under the users' home directory. The permissions for each of the subdirectories should be:
drwx------+  
 0: group:everyone deny delete

With the exception of the "Public" directory, whose permissions should match the following:
drwxr-xr-x+ 
 0: group:everyone deny delete

If the permissions returned by either of these checks differ from what is shown, this is a finding.)
  desc 'fix', 'To ensure the appropriate permissions are set for each user on the system, run the following command:

diskutil resetUserPermissions / userid, where userid is the user name for the user whose home directory permissions need to be repaired.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33772r607368_chk'
  tag severity: 'medium'
  tag gid: 'V-230827'
  tag rid: 'SV-230827r599842_rule'
  tag stig_id: 'APPL-11-002068'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-33745r607369_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00228', 'SRG-OS-000480-GPOS-00230']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
