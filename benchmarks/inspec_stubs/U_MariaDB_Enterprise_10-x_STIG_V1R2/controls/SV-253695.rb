control 'SV-253695' do
  title 'If MariaDB authentication, using passwords, is employed, then MariaDB must enforce the DoD standards for password complexity.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native MariaDB authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For MariaDB, the rules must be enforced using available configuration parameters or custom code.

By default, MariaDB Enterprise Server has the simple_password_check plugin installed and enabled. However, the default password requirements are eight character minimum, one numeric character, and one special character.'
  desc 'check', "Check the simple_password_check plugin variables to ensure they match the password requirements. 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'simple_password_check_%';

Determine whether the following rules are enforced. If they do not meet the following password requirements, this is a finding. 

a. minimum of 15 characters, including at least one of each of the following character sets:
- Uppercase
- Lowercase
- Numerics
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)

b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight"
  desc 'fix', 'Locate the MariaDB Enterprise Server configuration file (mariadb-enterprise.cnf) which contains the simple_password_check plugin variables within /etc/my.cnf.d/. Edit the variables. 

Example: 

simple_password_check_digits = 2
simple_password_check_letters_same_case = 2
simple_password_check_minimal_length = 15
simple_password_check_other_characters = 2'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57147r841608_chk'
  tag severity: 'high'
  tag gid: 'V-253695'
  tag rid: 'SV-253695r841610_rule'
  tag stig_id: 'MADB-10-003700'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-57098r841609_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
