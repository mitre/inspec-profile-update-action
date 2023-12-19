control 'SV-253668' do
  title 'MariaDB must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access MariaDB. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies.

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If MariaDB does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', "From the system security plan or equivalent documentation, determine the appropriate permissions on database objects for each kind (group role) of user. If this documentation is missing, this is a finding.

First, as the database administrator, check the privileges of all users and roles in the database.

Find all users:
MariaDB> SELECT user, host FROM mysql.user WHERE is_role = 'N';

Find all roles:
MariaDB> SELECT user FROM mysql.user WHERE is_role = 'Y';

For each user found, check grants:

MariaDB> SHOW GRANTS FOR 'username'@'host';

For each role found, check grants: 

MariaDB> SHOW GRANTS FOR 'rolename';

Review all users and roles and their associated privileges. If any users and/or roles privileges exceed those documented, this is a finding.

As the database administrator, check the configured authentication settings:

MariaDB> SHOW PLUGINS;

To find users not using PAM plugin for authentication: 

MariaDB> SELECT user, host, plugin FROM mysql.user WHERE plugin != 'pam';

If any users are returned, this is a finding. 

Review all entries and their associated authentication methods. If any entries do not have their documented authentication requirements, this is a finding."
  desc 'fix', "Create and/or maintain documentation of each group roles appropriate permissions on database objects.

Implement these permissions in the database and remove any permissions that exceed those documented.
 
The following are examples of how to use role privileges in MariaDB to enforce access controls. Run these as the database administrator.
For a complete list of privileges, see the official documentation: https://mariadb.com/kb/en/grant/ 

#### Roles Example 1
The following example demonstrates how to create an admin role with SHUTDOWN privileges.

As the database administrator, run the following SQL:

MariaDB> CREATE ROLE admin;
MariaDB> GRANT SHUTDOWN ON *.* TO admin;

#### Roles Example 2
The following example demonstrates how to create a user make the user a member of the admin role.

As the database administrator, run the following SQL:

MariaDB> CREATE USER 'admin_user'@'host' IDENTIFIED VIA PAM;
MariaDB> GRANT admin TO 'admin_user'@'%';

#### Roles Example 3
The following demonstrates how to revoke privileges from a role using REVOKE.

As the database administrator, run the following SQL:

MariaDB> REVOKE admin FROM 'admin_user'@'host';

#### Roles Example 4
The following demonstrates how to modify privileges for a role using GRANT.

As the database administrator, run the following SQL:

MariaDB> GRANT PROCESS ON *.* TO admin;

The following are examples of how to use grant privileges in MariaDB to enforce access controls on objects.

#### Grant Example 1
The following example demonstrates how to grant INSERT on a table to a role.

As the database administrator, run the following SQL:

MariaDB> GRANT INSERT ON test.t1 TO admin;

#### Grant Example 2
The following example demonstrates how to grant ALL PRIVILEGES on a table to a role.

As the database administrator, run the following SQL:

MariaDB> GRANT ALL PRIVILEGES ON test.t1 TO admin;

#### Grant Example 3
The following example demonstrates how to grant a role to a role.

As the database administrator, run the following SQL:

MariaDB> CREATE ROLE admin_master;
MariaDB> GRANT admin TO admin_master;

#### Revoke Example 1
The following example demonstrates how to revoke access from a role.

As the database administrator, run the following SQL:

MariaDB> REVOKE PROCESS ON *.* FROM admin;

To change authentication requirements for the database, as the OS administrator, review the configuration files /etc/pam.d and /etc/pam.conf. 

After changes to the configuration files /etc/pam.d and /etc/pam.conf, reload the server:
# SYSTEMD SERVER ONLY
$ sudo systemctl reload mariadb
# INITD SERVER ONLY
$ sudo service mariadb reload"
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57120r841527_chk'
  tag severity: 'high'
  tag gid: 'V-253668'
  tag rid: 'SV-253668r841529_rule'
  tag stig_id: 'MADB-10-000300'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-57071r841528_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
