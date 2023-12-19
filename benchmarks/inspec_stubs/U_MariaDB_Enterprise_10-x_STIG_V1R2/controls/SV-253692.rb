control 'SV-253692' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

MariaDB may spawn additional external processes to execute procedures that are defined in MariaDB but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than MariaDB and provide unauthorized access to the host system.'
  desc 'check', "MariaDB's LOAD DATA LOCAL INFILE command can interact with the server's underlying OS.  

To check the value of this option, run the following command as the database administrator: 

MariaDB>  SHOW GLOBAL VARIABLES LIKE 'local_infile'; 
 
Verify the option is set according to the security guide. If it is not, this is a finding. 
 
If the value of local_infile is set to ON per the security guide, user privileges must be checked. Only users with FILE privilege can use the LOAD DATA LOCAL INFILE command.

To check the users who have FILE privilege against the security guide, run the following commands as the database administrator.

1. Check which users have FILE privilege and GRANT OPTION privileges and compare to the security guide to determine if a user has FILE privilege that should not or if a user has GRANT OPTION and should not.  

If the users have privileges they should not have, this is a finding.

Run this script to create the SHOW GRANTS script for each user: 
MariaDB>  SELECT DISTINCT CONCAT( 'SHOW GRANTS FOR ', user,'@', host,';') AS grantQuery FROM mysql.user WHERE is_role = 'N';

Run each SHOW GRANTS command for each user.
MariaDB> SHOW GRANTS FOR 'user'@'host';
 
2. Check which roles have FILE privilege and GRANT OPTION privileges and compare to the security guide to determine if a role has FILE privilege that should not or if a role has GRANT OPTION and should not. 

If the roles have privileges they should not have, this is a finding.

MariaDB>  SELECT DISTINCT CONCAT('SHOW GRANTS FOR ',role, ';') FROM mysql.roles_mapping;

Run each SHOW GRANTS command for each role.
 
3. From the two outputs above, check which users and roles can set roles and grant privileges by checking who has GRANT OPTION and FILE privileges and comparing to the security guide.

If any user or role has GRANT OPTION or FILE privileges they should not have, this is a finding."
  desc 'fix', "To disable LOAD DATA LOCAL INFILE make the following update as the database administrator:

Edit the mariadb-enterprise.cnf configuration file located in /etc/my.cnf.d/.

Under [mariadb], add the following: 

local_infile = 0 

Save the configuration file. This change will not take effect until MariaDB Enterprise Server is restarted.  

To remove FILE and GRANT OPTION privileges use the right combination of the following commands:
1. revoke FILE privilege from a user
MariaDB> REVOKE FILE FROM 'user'@'host';

2. revoke FILE privilege from a role
MariaDB>  REVOKE FILE FROM role; 

3. revoke GRANT OPTION privilege from a user
MariaDB> REVOKE GRANT OPTION FROM 'user'@'host'; 

4. revoke a role grant from a user
MariaDB>  REVOKE ROLE FROM grantee;"
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57144r841599_chk'
  tag severity: 'medium'
  tag gid: 'V-253692'
  tag rid: 'SV-253692r841601_rule'
  tag stig_id: 'MADB-10-003400'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-57095r841600_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
