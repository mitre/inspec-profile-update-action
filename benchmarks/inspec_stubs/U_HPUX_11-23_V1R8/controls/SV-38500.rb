control 'SV-38500' do
  title 'Accounts must be locked upon 35 days of inactivity.'
  desc 'Inactive user accounts pose a risk to systems and applications. Owners of Inactive accounts will not notice if unauthorized access to their account has been obtained. There is a risk that inactive accounts can potentially be exploited to obtain and maintain undetected access to a system and/or application. The operating system must track periods of user account inactivity and disable all inactive accounts. Non-interactive accounts on the system, such as application accounts, may be documented exceptions.
Non-interactive accounts on the system, such as application accounts, may be documented exceptions.

Non-interactive accounts on the system, such as application accounts, may be documented exceptions.'
  desc 'check', 'For Trusted Mode:
Verify that user accounts are locked after 35 days of inactivity.
Note: The “u_llogin” attribute is stored in seconds: 86400 seconds/day * 35 days = 3024000 seconds.
# cd /tcb/files/auth && cat */* | egrep “:u_name=|:u_llogin=“

If user account is not set to lock after 35 days of inactivity, this is a finding.

For SMSE:
Check the INACTIVITY_MAXDAYS setting.
# grep  INACTIVITY_MAXDAYS /etc/default/security /var/adm/userdb/*

If INACTIVITY_MAXDAYS is set to 0 or greater than 35 for any user, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface to update the “u_llogin” (user last login) /tcb database attribute. See the /tcb database entry example below:
:u_llogin#3024000:

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the INACTIVITY_MAXDAYS attribute. See the below example:
INACTIVITY_MAXDAYS=35

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36270r3_chk'
  tag severity: 'medium'
  tag gid: 'V-918'
  tag rid: 'SV-38500r2_rule'
  tag stig_id: 'GEN000760'
  tag gtitle: 'GEN000760'
  tag fix_id: 'F-31527r3_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
