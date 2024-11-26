control 'SV-220264' do
  title 'The DBMS must limit the number of concurrent sessions for each system account to an organization-defined number of sessions.'
  desc 'Application management includes the ability to control the number of users and user sessions utilizing an application. Limiting the number of allowed users, and sessions per user, is helpful in limiting risks related to Denial of Service attacks.

This requirement addresses concurrent session control for a single information system account and does not address concurrent sessions by a single user via multiple system accounts.

Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to take into account the work requirements of the various types of user. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.'
  desc 'check', "Retrieve the settings for concurrent sessions for each profile with the query:
SELECT * FROM SYS.DBA_PROFILES WHERE RESOURCE_NAME = 'SESSIONS_PER_USER';

If the DBMS settings for concurrent sessions for each profile are greater than the site-specific maximum number of sessions, this is a finding."
  desc 'fix', 'Limit concurrent connections for each system account to a number less than or equal to the organization-defined number of sessions using the following SQL. Create profiles that conform to the requirements. Assign users to the appropriate profile.

The user profile, ORA_STIG_PROFILE, has been provided (starting with Oracle 12.1.0.2) to satisfy the STIG requirements pertaining to the profile parameters. Oracle recommends that this profile be customized with any site-specific requirements and assigned to all users where applicable.  Note: It remains necessary to create a customized replacement for the password validation function, ORA12C_STRONG_VERIFY_FUNCTION, if relying on this technique to verify password complexity.

The defaults for ORA_STIG_PROFILE are set as follows:
Resource Name                   Limit
-------------                   ------
COMPOSITE_LIMIT                 DEFAULT
SESSIONS_PER_USER               DEFAULT
CPU_PER_SESSION                 DEFAULT
CPU_PER_CALL                    DEFAULT
LOGICAL_READS_PER_SESSION       DEFAULT
LOGICAL_READS_PER_CALL          DEFAULT
IDLE_TIME                          15
CONNECT_TIME                    DEFAULT
PRIVATE_SGA                     DEFAULT
FAILED_LOGIN_ATTEMPTS               3 
PASSWORD_LIFE_TIME                 60
PASSWORD_REUSE_TIME               365
PASSWORD_REUSE_MAX                 10
PASSWORD_VERIFY_FUNCTION    ORA12C_STRONG_VERIFY_FUNCTION
PASSWORD_LOCK_TIME              UNLIMITED
PASSWORD_GRACE_TIME                 5

Change the value of SESSIONS_PER_USER (along with the other parameters, where relevant) from UNLIMITED to DoD-compliant, site-specific requirements and then assign users to the profile.
ALTER PROFILE ORA_STIG_PROFILE LIMIT SESSIONS_PER_USER <site-specific value>;

To assign the user to the profile do the following:
ALTER USER <username> PROFILE ORA_STIG_PROFILE;'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21979r391923_chk'
  tag severity: 'medium'
  tag gid: 'V-220264'
  tag rid: 'SV-220264r879511_rule'
  tag stig_id: 'O121-C2-000100'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-21971r391924_fix'
  tag 'documentable'
  tag legacy: ['SV-76457', 'V-61967']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
