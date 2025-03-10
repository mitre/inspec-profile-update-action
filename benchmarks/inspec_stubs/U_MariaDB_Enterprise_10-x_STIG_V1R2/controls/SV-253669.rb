control 'SV-253669' do
  title 'MariaDB must protect against a user falsely repudiating having performed organization-defined actions.'
  desc 'Nonrepudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Nonrepudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring MariaDB’s audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to MariaDB, even where the application connects to MariaDB with a standard, shared account.

It is recommended to not allow shared accounts, including root. The root user is known by all attackers, and often used in attempted attacks on the database servers.'
  desc 'check', 'All users should have individual accounts with appropriate privileges. The root user should be removed after administrative accounts with SUPER privilege are created. Query all users and determine if any are suspected shared accounts. Document any necessary shared accounts. 

MariaDB> SELECT user, host FROM mysql.user; 

Determine if any accounts are shared. A shared account is defined as a username, hostname, and password that are used by multiple individuals to log in to MariaDB. An example of a shared account is the MariaDB root account – root@localhost.

If accounts are determined to be shared, determine if individuals are first individually authenticated. 

If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding. 

The key is individual accountability. If this can be traced, this is not a finding.

If accounts are determined to be shared, determine if they are directly accessible to end users. If so, this is a finding.

Review contents of audit logs, traces, and data tables to confirm the identity of the individual user performing the action is captured.

If shared identifiers are found, and not accompanied by individual identifiers, this is a finding.'
  desc 'fix', "Remove shared accounts which are not documented and have been determined to not be necessary.

MariaDB> DROP USER 'user'@'hostname';"
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57121r841530_chk'
  tag severity: 'medium'
  tag gid: 'V-253669'
  tag rid: 'SV-253669r841532_rule'
  tag stig_id: 'MADB-10-000400'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-57072r841531_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
