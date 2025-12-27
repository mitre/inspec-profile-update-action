control 'SV-238448' do
  title 'The DBMS must specify an account lockout duration that is greater than or equal to the organization-approved minimum.'
  desc 'Anytime an authentication method is exposed, to allow for the utilization of an application, there is a risk that attempts will be made to obtain unauthorized access.

To defeat these attempts, organizations define the number of times a user account may consecutively fail a logon attempt. The organization also defines the period of time in which these consecutive failed attempts may occur.

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

User authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP.  This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "The account lockout duration is defined in the profile assigned to a user.

To see what profile is assigned to a user, enter the query:

SELECT profile FROM dba_users WHERE username = '&USERNAME'

This will return the profile name assigned to that user.

Now check the values assigned to the profile returned from the query above:

SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE LIKE '&PROFILE_NAME'  

Check the settings for password_lock_time - this specifies how long to lock the account after the number of consecutive failed logon attempts reaches the limit. If the value is not UNLIMITED, this is a finding."
  desc 'fix', "Configure the DBMS settings to specify indefinite lockout duration:

ALTER PROFILE '&PROFILE_NAME' LIMIT PASSWORD_LOCK_TIME UNLIMITED;"
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41659r667516_chk'
  tag severity: 'medium'
  tag gid: 'V-238448'
  tag rid: 'SV-238448r667518_rule'
  tag stig_id: 'O112-C2-004900'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41618r667517_fix'
  tag 'documentable'
  tag legacy: ['V-52407', 'SV-66623']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
