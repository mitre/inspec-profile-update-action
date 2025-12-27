control 'SV-38488' do
  title 'All interactive users must be assigned a home directory in the /etc/passwd file.'
  desc 'If users do not have a valid home directory, there is no place for the storage and control of files they own.'
  desc 'check', 'Verify the consistency of the assigned home directories in the authentication database.
For Trusted Mode:
# authck -av

If any user is not assigned a home directory, this is a finding.

For SMSE:
# pwck

If any user is not assigned a home directory, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Determine why the user is not assigned a home directory. Possible actions include: account deletion or disablement. If the account is determined to be valid, manually create the home directory if required (mkdir directoryname, copy the skeleton files into the directory, chown account name for the new directory and the skeleton files) and assign to the user in the /etc/passwd file or take corrective action via the HP SMH/SAM utility. 

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Determine why the user is not assigned a home directory. Possible actions include: account deletion or disablement. If the account is determined to be valid, manually create the home directory if required (mkdir directoryname, copy the skeleton files into the directory, chown account name for the new directory and the skeleton files) and assign to the user in the /etc/passwd file or take corrective action via the HP SMH/SAM utility. 

Additionally, use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the ABORT_LOGIN_ON_MISSING_HOMEDIR attribute. See the below example:
ABORT_LOGIN_ON_MISSING_HOMEDIR=1
Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36333r3_chk'
  tag severity: 'low'
  tag gid: 'V-899'
  tag rid: 'SV-38488r2_rule'
  tag stig_id: 'GEN001440'
  tag gtitle: 'GEN001440'
  tag fix_id: 'F-31588r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
