control 'SV-237714' do
  title 'The DBMS must set the maximum number of consecutive invalid logon attempts to three.'
  desc 'Anytime an authentication method is exposed,  to allow for the utilization of an application, there is a risk that attempts will be made to obtain unauthorized access.

To defeat these attempts, organizations define the number of times a user account may consecutively fail a logon attempt. The organization also defines the period of time in which these consecutive failed attempts may occur.

By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

More recent brute force attacks make attempts over long periods of time to circumvent intrusion detection systems and system account lockouts based entirely on the number of failed logons that are typically reset after a successful logon.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP.  This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.

Note also that a policy that places no limit on the length of the timeframe (for counting consecutive invalid attempts) does satisfy this requirement.'
  desc 'check', 'The limit on the number of consecutive failed logon attempts is defined in the profile assigned to a user.

Check the FAILED_LOGIN_ATTEMPTS value assigned to the profiles returned from this query:
SQL>SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES;

Check the setting for FAILED_LOGIN_ATTEMPTS - this is the number of consecutive failed logon attempts before locking the Oracle user account. If the value is greater than three on any of the profiles, this is a finding.'
  desc 'fix', 'Configure the DBMS setting to specify the maximum number of consecutive failed logon attempts to three (or less):
ALTER PROFILE {PROFILE_NAME} LIMIT FAILED_LOGIN_ATTEMPTS 3;

(ORA_STIG_PROFILE is available in DBA_PROFILES, starting with Oracle 12.1.0.2. Note: It remains necessary to create a customized replacement for the password validation function, ORA12C_STRONG_VERIFY_FUNCTION, if relying on this technique to verify password complexity.)'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40933r667172_chk'
  tag severity: 'medium'
  tag gid: 'V-237714'
  tag rid: 'SV-237714r667174_rule'
  tag stig_id: 'O121-C2-005000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40896r667173_fix'
  tag 'documentable'
  tag legacy: ['V-61605', 'SV-76095']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
