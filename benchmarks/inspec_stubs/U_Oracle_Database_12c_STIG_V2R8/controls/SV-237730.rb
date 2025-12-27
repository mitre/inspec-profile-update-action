control 'SV-237730' do
  title 'The DBMS must support organizational requirements to enforce password complexity by the number of numeric characters used.'
  desc 'Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Use of a complex password helps to increase the time and resources required to compromise the password.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP  This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "If all user accounts are managed and authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle's control, determine the password verification function, if any, that is in use:

SELECT * FROM SYS.DBA_PROFILES
WHERE RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
[AND PROFILE NOT IN (<list of non-applicable profiles>)]
ORDER BY PROFILE;
Bearing in mind that a profile can inherit from another profile, and the root profile is called DEFAULT, determine the name of the password verification function effective for each profile.

If, for any profile, the function name is null, this is a finding.

For each password verification function, examine its source code.

If it does not enforce the organization-defined minimum number of numeric characters (1 unless otherwise specified), this is a finding."
  desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

If any user accounts are managed by Oracle: Develop, test, and implement a password verification function that enforces DoD requirements.

Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION. This can be used as the starting point for a customized function. The script file is found in the following location on the server depending on OS:
Windows:
%ORACLE_HOME%\\RDBMS\\ADMIN\\catpvf.sql
UNIX/Linux:
$ORACLE_HOME/rdbms/admin/catpvf.sql'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40949r667220_chk'
  tag severity: 'medium'
  tag gid: 'V-237730'
  tag rid: 'SV-237730r879601_rule'
  tag stig_id: 'O121-C2-014300'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-40912r667221_fix'
  tag 'documentable'
  tag legacy: ['V-61727', 'SV-76217']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
