control 'SV-235137' do
  title 'If Database Management System (DBMS) authentication using passwords is employed, the DBMS must enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when circumstances make it unavoidable; and must be documented and Authorizing Official (AO)-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so.  For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', %q(If DBMS authentication using passwords is not employed, this is not a finding.

If the DBMS is configured to inherit password complexity and lifetime rules from the operating system or access control program, this is not a finding.

Review the MySQL Database Server 8.0 settings relating to password complexity. Determine whether the following rules are enforced. If any are not, this is a finding.
a. minimum of 15 characters, including at least one of each of the following character sets:
- Uppercase
- Lowercase
- Numeric
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight

Review the DBMS settings relating to password lifetime. Determine whether the following rules are enforced. If any are not, this is a finding.
a. Password lifetime limits for interactive accounts: Minimum 24 hours, maximum 60 days
b. Password lifetime limits for non-interactive accounts: Minimum 24 hours, maximum 365 days
c. Number of password changes before an old one may be reused: Minimum of five

Connect as an admin. 

SELECT component_urn FROM mysql.component
where component_urn='file://component_validate_password' group by component_urn;

If the "validate password" component is installed the result will be file://component_validate_password.

If "validate password" component is not installed, this is a finding.

If the "component_validate_password" is installed, review the password policies to ensure required password complexity is met. 

Run the following to review the password policy:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where VARIABLE_NAME like 'valid%password%' or VARIABLE_NAME like 'password_%'  ;

For example the results may look like the following:
'validate_password.check_user_name',’ON’
'validate_password.dictionary_file',''
'validate_password.length','8'
'validate_password.mixed_case_count','1'
'validate_password.number_count','1'
'validate_password.policy','MEDIUM'
'validate_password.special_char_count','1'
'password_reuse_interval','0'
'password_require_current','OFF'
'password_history','0'

If these results do not meet password complexity requirements listed above, this is a finding.)
  desc 'fix', "If the use of passwords is not needed, configure the MySQL Database Server 8.0 to prevent their use if it is capable of this; if it is not so capable, institute policies and procedures to prohibit their use.

If the MySQL Database Server 8.0 can inherit password complexity rules from the operating system or access control program, configure it to do so.

Otherwise, use MySQL Database Server 8.0 configuration parameters and/or custom code to enforce the following rules for passwords:

a. minimum of 15 characters, including at least one of each of the following character sets:
- Uppercase
- Lowercase
- Numeric
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight
c. Password lifetime limits for interactive accounts: Minimum 24 hours, maximum 60 days
d. Password lifetime limits for non-interactive accounts: Minimum 24 hours, maximum 365 days
e. Number of password changes before an old one may be reused: Minimum of five  

As the database admin:

INSTALL COMPONENT 'file://component_validate_password';

# Set Password Policies - For Example
set persist validate_password.check_user_name='ON';
set persist validate_password.dictionary_file='<FILENAME OF DICTIONARY FILE';
set persist validate_password.length=15;
set persist validate_password.mixed_case_count=1;
set persist validate_password.special_char_count=2;
set persist validate_password.number_count=2;
set persist validate_password.policy='STRONG';
set persist password_history = 5;
set persist password_reuse_interval = 365;
SET GLOBAL default_password_lifetime = 180;

Optional
set persist password_require_current=YES

This can also be set at the account level:
ALTER USER 'jeffrey'@'localhost'
  PASSWORD HISTORY 5
  PASSWORD REUSE INTERVAL 365 DAY;
ALTER USER 'jeffrey'@'localhost' PASSWORD EXPIRE INTERVAL 90 DAY;"
  impact 0.7
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38356r623531_chk'
  tag severity: 'high'
  tag gid: 'V-235137'
  tag rid: 'SV-235137r623533_rule'
  tag stig_id: 'MYS8-00-005000'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-38319r623532_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
