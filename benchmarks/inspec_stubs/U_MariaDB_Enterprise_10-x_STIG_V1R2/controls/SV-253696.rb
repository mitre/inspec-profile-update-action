control 'SV-253696' do
  title 'If MariaDB authentication using passwords is employed, MariaDB must enforce the DoD standards for password lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native MariaDB authentication may be used only when circumstances make it unavoidable and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For MariaDB, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', "Check the default password lifetime variable to verify it matches the password requirement. 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'default_password_lifetime%';

If the value returned is not 60 or less, this is a finding."
  desc 'fix', 'Locate the MariaDB Enterprise Server configuration file (mariadb-enterprise.cnf) that contains the password variables within /etc/my.cnf.d/. Edit the variables. 

Example: 

default_password_lifetime = 60'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57148r841611_chk'
  tag severity: 'medium'
  tag gid: 'V-253696'
  tag rid: 'SV-253696r841613_rule'
  tag stig_id: 'MADB-10-003750'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-57099r841612_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
