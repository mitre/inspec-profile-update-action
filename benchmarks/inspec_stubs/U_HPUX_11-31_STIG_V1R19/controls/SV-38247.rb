control 'SV-38247' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password guessing attacks to run against a single password.'
  desc 'check', "For Trusted Mode:
Check the exptm field for each user, or for all accounts:
# getprpw -r -m exptm <USER>
# logins -o -x | awk -F: '{print $1” “$11}' 

If the exptm attribute is set equal to -1, 0, or greater than 60 for any user, this is a finding.

For SMSE:
Check the PASSWORD_MAXDAYS setting. The command and an example output is seen directly below:
# egrep “PASSWORD_MAXDAYS|PASSWORD_WARNDAYS” /etc/default/security /var/adm/userdb/*

Example output from the above command, with the correctly assigned attribute values. Note that PASSWORD_MAXDAYS may deviate from 60. Illegal values include 0 (no warning).  PASSWORD_MAXDAYS attribute exceptions that must not be used are 1-7 (values less than or equal to the required PASSWORD_WARNDAYS attribute setting):
PASSWORD_MAXDAYS=60
PASSWORD_WARNDAYS=7

If the above attributes are either missing or not set per the above attribute values (exceptions noted above), this is a finding."
  desc 'fix', 'For Trusted Mode:
Set the password maximum days field to 60 for all user accounts.
# passwd -x 60 <user>

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the PASSWORD_MAXDAYS attribute. See the below example:
PASSWORD_MAXDAYS=60
PASSWORD_WARNDAYS=7

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36288r3_chk'
  tag severity: 'medium'
  tag gid: 'V-11976'
  tag rid: 'SV-38247r3_rule'
  tag stig_id: 'GEN000700'
  tag gtitle: 'GEN000700'
  tag fix_id: 'F-31545r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000180']
  tag nist: ['IA-5 f']
end
