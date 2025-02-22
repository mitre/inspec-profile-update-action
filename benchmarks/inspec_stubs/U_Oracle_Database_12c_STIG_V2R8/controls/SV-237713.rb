control 'SV-237713' do
  title 'The DBMS must verify account lockouts persist until reset by an administrator.'
  desc 'Anytime an authentication method is exposed, to allow for the utilization of an application, there is a risk that attempts will be made to obtain unauthorized access.

To defeat these attempts, organizations define the number of times a user account may consecutively fail a logon attempt. The organization also defines the period of time in which these consecutive failed attempts may occur.

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "The account lockout duration is defined in the profile assigned to a user.

To see what profile is assigned to a user, enter the query:

SQL>SELECT profile FROM dba_users WHERE username = '<username>'

This will return the profile name assigned to that user.

The user profile, ORA_STIG_PROFILE, has been provided (starting with Oracle 12.1.0.2) to satisfy the STIG requirements pertaining to the profile parameters. Oracle recommends that this profile be customized with any site-specific requirements and assigned to all users where applicable.  Note: It remains necessary to create a customized replacement for the password validation function, ORA12C_STRONG_VERIFY_FUNCTION, if relying on this technique to verify password complexity.

Now check the values assigned to the profile returned from the query above:

column profile format a20
column limit format a20
SQL>SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE = 'ORA_STIG_PROFILE';

Check the settings for password_lock_time - this specifies how long to lock the account after the number of consecutive failed logon attempts reaches the limit. If the value is not UNLIMITED, this is a finding."
  desc 'fix', 'Configure the DBMS settings to specify indefinite lockout duration:
ALTER PROFILE ORA_STIG_PROFILE LIMIT PASSWORD_LOCK_TIME UNLIMITED;'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40932r667169_chk'
  tag severity: 'medium'
  tag gid: 'V-237713'
  tag rid: 'SV-237713r879887_rule'
  tag stig_id: 'O121-C2-004900'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40895r667170_fix'
  tag 'documentable'
  tag legacy: ['V-61603', 'SV-76093']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
