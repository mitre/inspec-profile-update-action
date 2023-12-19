control 'SV-238462' do
  title 'The DBMS must support organizational requirements to prohibit password reuse for the organization-defined number of generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals.  

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements. 

Password reuse restrictions protect against bypass of password expiration requirements and help protect accounts from password guessing attempts.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP  This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle's control, determine the password reuse rule, if any, that is in effect:
SELECT * FROM SYS.DBA_PROFILES 
WHERE RESOURCE_NAME IN ('PASSWORD_REUSE_MAX', 'PASSWORD_REUSE_TIME')
[AND PROFILE NOT IN (<list of non-applicable profiles>)]
ORDER BY PROFILE, RESOURCE_NAME;
Bearing in mind that a profile can inherit from another profile, and the root profile is called DEFAULT, determine the value of the PASSWORD_REUSE_MAX effective for each profile.

If, for any profile, the PASSWORD_REUSE_MAX value does not enforce the DoD-defined minimum number of password changes before a password may be repeated (5 or greater), this is a finding.  PASSWORD_REUSE_MAX is effective if and only if PASSWORD_REUSE_TIME is specified, so if both are UNLIMITED, this is a finding."
  desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

If any user accounts are managed by Oracle:  For each profile, set the PASSWORD_REUSE_MAX to enforce the DoD-defined minimum number of password changes before a password may be repeated (5 or greater).  

PASSWORD_REUSE_MAX is effective if and only if PASSWORD_REUSE_TIME is specified, so ensure also that it has a meaningful value.  Since the minimum password lifetime is 1 day, the smallest meaningful value is the same as the PASSWORD_REUSE_MAX value.

Using PPPPPP as an example, the statement to do this is:
ALTER PROFILE PPPPPP LIMIT PASSWORD_REUSE_MAX 5 PASSWORD_REUSE_TIME 5;'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41673r667558_chk'
  tag severity: 'medium'
  tag gid: 'V-238462'
  tag rid: 'SV-238462r667560_rule'
  tag stig_id: 'O112-C2-014000'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-41632r667559_fix'
  tag 'documentable'
  tag legacy: ['V-52273', 'SV-66489']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
