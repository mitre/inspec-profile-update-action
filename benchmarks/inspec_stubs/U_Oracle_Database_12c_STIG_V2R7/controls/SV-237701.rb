control 'SV-237701' do
  title 'The DBMS must provide a mechanism to automatically identify accounts designated as temporary or emergency accounts.'
  desc 'Temporary application accounts could be used in the event of a vendor support visit where a support representative requires a temporary unique account in order to perform diagnostic testing or conduct some other support-related activity. When these types of accounts are created, there is a risk that the temporary account may remain in place and active after the support representative has left.

To address this, in the event temporary application accounts are required, the application must ensure accounts designated as temporary in nature shall automatically terminate these accounts after an organization-defined time period.  Such a process and capability greatly reduces the risk that accounts will be misused, hijacked, or data compromised.

Note that user authentication and account management should be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.

Temporary database accounts must be identified in order for the system to recognize and terminate them after a given time period. The DBMS and any administrators must have a means to recognize any temporary accounts for special handling.'
  desc 'check', ": If the organization has a policy, consistently enforced, forbidding the creation of emergency or temporary accounts, this is not a finding.

If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism and not by Oracle, this is not a finding.

If using the database to identify temporary accounts, and temporary accounts exist, there should be a temporary profile. If a profile for temporary accounts cannot be identified, this is a finding.

To check for a temporary profile, run the scripts below:

To obtain a list of profiles:
SELECT PROFILE#, NAME FROM SYS.PROFNAME$;

To obtain a list of users assigned a given profile (TEMPORARY_USERS, in this example):
SELECT USERNAME, PROFILE FROM SYS.DBA_USERS
WHERE PROFILE = 'TEMPORARY_USERS'
ORDER BY USERNAME;"
  desc 'fix', 'Use a profile with a distinctive name (for example, TEMPORARY_USERS), so that temporary users can be easily identified. Whenever a temporary user account is created, assign it to this profile.

To enable resource limiting via profiles, use the SQL statement:
ALTER SYSTEM SET RESOURCE_LIMIT = TRUE;

Set values in the profile as needed for temporary users - see below for further information. The values here are examples; set them to values appropriate to the situation:

CREATE PROFILE TEMPORARY_USERS
LIMIT
SESSIONS_PER_USER <limit>
CPU_PER_SESSION <limit>
CPU_PER_CALL <limit>
CONNECT_TIME <limit>
LOGICAL_READS_PER_SESSION DEFAULT
LOGICAL_READS_PER_CALL <limit>
PRIVATE_SGA <limit>
COMPOSITE_LIMIT <limit>
FAILED_LOGIN_ATTEMPTS 3
PASSWORD_LIFE_TIME 7
PASSWORD_REUSE_TIME 60
PASSWORD_REUSE_MAX 5
PASSWORD_VERIFY_FUNCTION ORA12c_STRONG_VERIFY_FUNCTION
PASSWORD_LOCK_TIME UNLIMITED
PASSWORD_GRACE_TIME 3;
CREATE USER <username> IDENTIFIED BY <password> PROFILE TEMPORARY_USERS;

Resource Parameters:

COMPOSITE_LIMIT - Specify the total resource cost for a session, expressed in service units. Oracle Database calculates the total service units as a weighted sum of CPU_PER_SESSION, CONNECT_TIME,
LOGICAL_READS_PER_SESSION, and PRIVATE_SGA.

SESSIONS_PER_USER - Specify the number of concurrent sessions to limit the user to.

CPU_PER_SESSION - Specify the CPU time limit for a session, expressed in hundredths of seconds.

CPU_PER_CALL - Specify the CPU time limit for a call (a parse, execute, or fetch), expressed in hundredths of seconds.

LOGICAL_READS_PER_SESSION - Specify the permitted number of data blocks read in a session, including blocks read from memory and disk.

LOGICAL_READS_PER_CALL - Specify the permitted number of data blocks read for a call to process a SQL statement (a parse, execute, or fetch).

PRIVATE_SGA - Specify the amount of private space a session can allocate in the shared pool of the system global area (SGA). Refer to size_clause for information on that clause.

CONNECT_TIME - Specify the total elapsed time limit for a session, expressed in minutes.

IDLE_TIME - Specify the permitted periods of continuous inactive time during a session, expressed in minutes. Long-running queries and other operations are not subject to this limit.

COMPOSITE_LIMIT - See Oracle documentation for more details.


Password Parameters

Use the following clauses to set password parameters. Parameters that set lengths of time are interpreted in number of days. For testing purposes, specify minutes (n/1440) or even seconds (n/86400).

FAILED_LOGIN_ATTEMPTS - Specify the number of failed attempts to log on to the user account before the account is locked. If omitting this clause, then the default is 10 times.

PASSWORD_LIFE_TIME - Specify the number of days the same password can be used for authentication. If setting a value for PASSWORD_GRACE_TIME, then the password expires if it is not changed within the grace period, and further connections are rejected. If omitting this clause, then the default is 180 days.

PASSWORD_REUSE_TIME and PASSWORD_REUSE_MAX - These two parameters must be set in conjunction with each other. PASSWORD_REUSE_TIME specifies the number of days before which a password cannot be reused. PASSWORD_REUSE_MAX specifies the number of password changes required before the current password can be reused. For these parameters to have any effect, specify an integer for both of them.

If specifying a value for both of these parameters, then the user cannot reuse a password until the password has been changed the number of times specified for PASSWORD_REUSE_MAX during the number of days specified for PASSWORD_REUSE_TIME.

For example, if specifying PASSWORD_REUSE_TIME to 30 and PASSWORD_REUSE_MAX to 10, then the user can reuse the password after 30 days if the password has already been changed 10 times.

If specifying a value for either of these parameters and specify UNLIMITED for the other, then the user can never reuse a password.

If specifying DEFAULT for either parameter, then Oracle Database uses the value defined in the DEFAULT profile. By default, all parameters are set to UNLIMITED in the DEFAULT profile. If the default setting of UNLIMITED in the DEFAULT profile has not changed, then the database treats the value for that parameter as UNLIMITED.

If setting both of these parameters to UNLIMITED, then the database ignores both of them. This is the default if omitting both parameters.

PASSWORD_LOCK_TIME - Specify the number of days an account will be locked after the specified number of consecutive failed logon attempts. If omitting this clause, then the default is 1 day.

PASSWORD_GRACE_TIME - Specify the number of days after the grace period begins during which a warning is issued and logon is allowed. If omitting this clause, then the default is 7 days.

PASSWORD_VERIFY_FUNCTION - The PASSWORD_VERIFY_FUNCTION clause lets a PL/SQL password complexity verification script be passed as an argument to the CREATE PROFILE statement. Oracle Database provides a default script, but can create your own routine or use third-party software instead.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40920r667133_chk'
  tag severity: 'medium'
  tag gid: 'V-237701'
  tag rid: 'SV-237701r879887_rule'
  tag stig_id: 'O121-C2-001900'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40883r667134_fix'
  tag 'documentable'
  tag legacy: ['V-61559', 'SV-76049']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
