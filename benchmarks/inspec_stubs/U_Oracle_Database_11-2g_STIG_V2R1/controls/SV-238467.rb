control 'SV-238467' do
  title 'The DBMS must support organizational requirements to enforce the number of characters that get changed when passwords are changed.'
  desc 'Passwords need to be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse extensive portions of their password when they change their password, the end result is a password that has not had enough elements changed to meet the policy requirements.

Changing passwords frequently can thwart password-guessing attempts or re-establish protection of a compromised DBMS account. Minor changes to passwords may not accomplish this since password guessing may be able to continue to build on previous guesses, or the new password may be easily guessed using the old password.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP  This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle's control, determine the password verification function, if any, that is in use:

SELECT * FROM SYS.DBA_PROFILES 
WHERE RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
[AND PROFILE NOT IN (<list of non-applicable profiles>)]
ORDER BY PROFILE;
Bearing in mind that a profile can inherit from another profile, and the root profile is called DEFAULT, determine the name of the password verification function effective for each profile.

If, for any profile, the function name is null, this is a finding.  

For each password verification function, examine its source code.  If it does not enforce the organization-defined minimum number of characters by which the password must differ from the previous password (eight of the characters unless otherwise specified), this is a finding."
  desc 'fix', 'If any user accounts are managed by Oracle:  Develop, test and implement a password verification function that enforces DoD requirements.

(Oracle supplies a sample function called verify_function_11G, in the script file 
<oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point for a customized function.)'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41678r667573_chk'
  tag severity: 'medium'
  tag gid: 'V-238467'
  tag rid: 'SV-238467r667575_rule'
  tag stig_id: 'O112-C2-014500'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-41637r667574_fix'
  tag 'documentable'
  tag legacy: ['V-52283', 'SV-66499']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
