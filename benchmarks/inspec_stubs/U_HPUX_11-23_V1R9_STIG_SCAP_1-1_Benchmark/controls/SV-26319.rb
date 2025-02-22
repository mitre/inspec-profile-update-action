control 'SV-26319' do
  title 'The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.'
  desc 'Limiting simultaneous user logins can insulate the system from Denial of Service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.

If the defined value of 10 logins does not meet operational requirements, the site may define the permitted number of simultaneous login sessions based on operational requirements.

This limit is for the number of simultaneous login sessions for EACH user account. This is NOT a limit on the total number of simultaneous login sessions on the system.'
  desc 'fix', 'For Trusted Mode:
Use the SAM/SMH interface (/etc/default/security file) to update attribute. See the below example:
NUMBER_OF_LOGINS_ALLOWED=10

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update attribute. See the below example:
NUMBER_OF_LOGINS_ALLOWED=10

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-22298'
  tag rid: 'SV-26319r2_rule'
  tag stig_id: 'GEN000450'
  tag gtitle: 'GEN000450'
  tag fix_id: 'F-31517r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
