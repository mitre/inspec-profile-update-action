control 'SV-237732' do
  title 'The DBMS must support organizational requirements to enforce the number of characters that get changed when passwords are changed.'
  desc 'Passwords need to be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse extensive portions of their password when they change their password, the end result is a password that has not had enough elements changed to meet the policy requirements.

Changing passwords frequently can thwart password-guessing attempts or re-establish protection of a compromised DBMS account. Minor changes to passwords may not accomplish this since password guessing may be able to continue to build on previous guesses, or the new password may be easily guessed using the old password.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP  This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "If all user accounts are managed and authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle's control, determine the password verification function, if any, that is in use:

SELECT * FROM SYS.DBA_PROFILES
WHERE RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
[AND PROFILE NOT IN (<list of non-applicable profiles>)] ORDER BY PROFILE;

Bearing in mind that a profile can inherit from another profile, and the root profile is called DEFAULT, determine the name of the password verification function effective for each profile.

If, for any profile, the function name is null, this is a finding.

For each password verification function, examine its source code.

If it does not enforce the organization-defined minimum number of characters by which the password must differ from the previous password (eight of the characters unless otherwise specified), this is a finding."
  desc 'fix', 'If any user accounts are managed by Oracle: Develop, test, and implement a password verification function that enforces DoD requirements.

Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION. This can be used as the starting point for a customized function. The script file is found in the following location on the server depending on OS:
Windows:
%ORACLE_HOME%\\RDBMS\\ADMIN\\catpvf.sql
UNIX/Linux:
$ORACLE_HOME/rdbms/admin/catpvf.sql'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40951r667226_chk'
  tag severity: 'medium'
  tag gid: 'V-237732'
  tag rid: 'SV-237732r667228_rule'
  tag stig_id: 'O121-C2-014500'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-40914r667227_fix'
  tag 'documentable'
  tag legacy: ['V-61731', 'SV-76221']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
