control 'SV-209607' do
  title 'The macOS system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.'
  desc "Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources."
  desc 'check', %q(For each listing, with the exception of "Shared", verify that the directory is owned by the username, that only the owner has "write" permissions, and the correct Access Control Entry is listed.

To verify permissions on users' home directories, use the following command:

# ls -le /Users

drwxr-xr-x+ 12 Guest        _guest  384 Apr  2 09:40 Guest

 0: group:everyone deny delete

drwxrwxrwt   4 root         wheel   128 Mar 28 05:53 Shared

drwxr-xr-x+ 13 admin        staff   416 Apr  8 08:58 admin

 0: group:everyone deny delete

drwxr-xr-x+ 11 test         user   352 Apr  8 09:00 test

 0: group:everyone deny delete
 
If the directory is not owned by the user, this is a finding.

If anyone other than the user has "write" permissions to the directory, this is a finding.

If the Access Control Entry listed is not "0: group:everyone deny delete", this is a finding.)
  desc 'fix', %q(To reset the permissions on a users' home directory to their defaults, run the following command, where "username" is the user's short name:

sudo diskutil resetUserPermissions / username)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9858r282303_chk'
  tag severity: 'medium'
  tag gid: 'V-209607'
  tag rid: 'SV-209607r610285_rule'
  tag stig_id: 'AOSX-14-002065'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-9858r282304_fix'
  tag 'documentable'
  tag legacy: ['SV-104721', 'V-95533']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
