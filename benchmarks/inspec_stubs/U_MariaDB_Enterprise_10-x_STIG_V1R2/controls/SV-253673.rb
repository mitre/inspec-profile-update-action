control 'SV-253673' do
  title 'MariaDB must be able to generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. MariaDB makes such information available through an audit log file.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that MariaDB continually performs to determine if any and every action on the database is permitted.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "As the database administrator, create a user by running the following SQL:

MariaDB> CREATE USER 'test_user'@'localhost' IDENTIFIED BY 'test_user_password';

In one terminal, tail the audit log file:

tail -F /var/lib/mysql/server_audit.log (default location)

In another terminal attempt to retrieve information from the MariaDB table, mysql.roles_mapping, by logging in as the test_user and running a query which it does not have privileges to do, for example: 

$ mariadb -u test_user -p

MariaDB> SELECT * FROM mysql.roles_mapping;
  
The audit log will show:
20190321 21:39:20,5a7e16cc51f7, test_user ,localhost,127,394,QUERY,, select * from mysql.roles_mapping ,1142
  
To find failed queries, look for two elements: The notation indicating that it is a QUERY entry, and the last value for the entry. If the query is unsuccessful, the value will be NOT EQUAL TO 0.
  
If the above steps cannot verify that audit records are produced when MariaDB denies retrieval of privileges/permissions/role memberships, this is a finding. 

If an audit record is not produced in the first terminal, this is a finding."
  desc 'fix', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Update the filters as necessary."
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57125r841542_chk'
  tag severity: 'medium'
  tag gid: 'V-253673'
  tag rid: 'SV-253673r841544_rule'
  tag stig_id: 'MADB-10-000800'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag fix_id: 'F-57076r841543_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
