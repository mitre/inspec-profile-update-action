control 'SV-38248' do
  title 'The system must log successful and unsuccessful access to the root account.'
  desc 'If successful and unsuccessful logins and logouts are not monitored or recorded, access attempts cannot be tracked.  Without this logging, it may be impossible to track unauthorized access to the system.'
  desc 'check', 'Check the following log files to determine if access attempts to the root account are being logged. Try su - and enter an incorrect password.
# more /var/adm/sulog /var/adm/syslog

If root account access login attempts are not being logged, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Ensure that all users are being audited. List users from the passwd file and check the user entries in the /tcb database. See the example below. Note that the “getprpw” command must be executed individually for all users. Users associated with “audflg” set to zero (disabled) must be corrected.
# cat /etc/passwd | cut -f 1,1 -d “:”
# getprpw -m audflg <user>
# modprpw -l -m audflg=1 <user>

Use the SAM/SMH interface (/etc/default/security file) to update the SU_ROOT_GROUP attribute. See the below example:
SU_ROOT_GROUP=root,<user1>,<user2>

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the AUDIT_FLAG and SU_ROOT_GROUP attributes. See the below example:
AUDIT_FLAG=1
SU_ROOT_GROUP=root,<user1>,<user2>

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36291r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11980'
  tag rid: 'SV-38248r2_rule'
  tag stig_id: 'GEN001060'
  tag gtitle: 'GEN001060'
  tag fix_id: 'F-31548r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
