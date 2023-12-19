control 'SV-253732' do
  title 'MariaDB must enforce access restrictions associated with changes to the configuration of MariaDB or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', "To list all the permissions of individual roles, as the database administrator, run the following SQL:
 
1. For User privileges:

Gather a list of SHOW GRANTS commands. SHOW GRANTS will list the privileges granted to the account.

Run this script to create the SHOW GRANTS script for each user: 
MariaDB> SELECT DISTINCT CONCAT( 'SHOW GRANTS FOR ', user,'@', host,';') AS grantQuery FROM mysql.user WHERE is_role = 'N';

Run each SHOW GRANTS command for each user.

2. For role privileges (except admin_option, whether the role can be granted by a particular use):

  MariaDB> SELECT CONCAT('SHOW GRANTS FOR ',Role,';' ) FROM mysql.roles_mapping;
 
Run each SHOW GRANTS command for each role.

If any role has admin_option that should not, this is a finding.

There are no privileges assigned to databases or tables, security is enforced through the traditional way with granting very specific user privileges.
 
If any database or schema has update or create privileges and should not, this is a finding."
  desc 'fix', 'Configure MariaDB to enforce access restrictions associated with changes to the configuration of MariaDB or database(s). 
 
1. Use REVOKE to revoke privileges or roles on objects from users.
 
MariaDB>  REVOKE  privileges  ON  object  FROM  user ;
 
2. Use REVOKE to remove a role from a user or another role that it was previously assigned to.
 
MariaDB>  REVOKE  role  FROM  grantee or role ;'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57184r841719_chk'
  tag severity: 'medium'
  tag gid: 'V-253732'
  tag rid: 'SV-253732r841721_rule'
  tag stig_id: 'MADB-10-007900'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-57135r841720_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
