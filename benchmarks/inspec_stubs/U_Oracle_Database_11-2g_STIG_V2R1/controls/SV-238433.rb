control 'SV-238433' do
  title 'DBMS default accounts must be assigned custom passwords.'
  desc "Password maximum lifetime is  the maximum period of time, (typically in days) a user's password may be in effect before the user is forced to change it.

Passwords need to be changed at specific policy-based intervals as per policy. Any password, no matter how complex, can eventually be cracked.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

DBMS default passwords provide a commonly known and exploited means for unauthorized access to database installations."
  desc 'check', 'Use this query to identify the Oracle-supplied accounts that still have their default passwords:

SELECT * FROM SYS.DBA_USERS_WITH_DEFPWD;

If any accounts other than XS$NULL are listed, this is a finding.

(XS$NULL is an internal account that represents the absence of a user in a session. Because XS$NULL is not a user, this  account can only be accessed by the Oracle Database instance. XS$NULL has no privileges and no one can authenticate as XS$NULL, nor can authentication credentials ever be assigned to XS$NULL.)'
  desc 'fix', 'Change passwords for DBMS accounts to non-default values. Where necessary, unlock or enable accounts to change the password, and then return the account to disabled or locked status.'
  impact 0.7
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41644r667471_chk'
  tag severity: 'high'
  tag gid: 'V-238433'
  tag rid: 'SV-238433r667473_rule'
  tag stig_id: 'O112-C1-015000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41603r667472_fix'
  tag 'documentable'
  tag legacy: ['V-52329', 'SV-66545']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
