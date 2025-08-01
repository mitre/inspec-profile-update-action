control 'SV-224133' do
  title 'The EDB Postgres Advanced Server must protect against a user falsely repudiating by ensuring all accounts are individual, unique, and not shared.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables, and configuring the DBMS' audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, group account."
  desc 'check', %q(If there are no shared accounts available to more than one user, this is not a finding.

If a shared account is used by an application to interact with the database, review the System Security Plan, the tables in the database, and the application source code/documentation to determine whether the application captures the individual user's identity and stores that identity in the audit log or along with all data inserted and updated (also with all records of reads and/or deletions, if these are required to be logged).

The EDB audit feature provides the ability to include application user information with the database audit log using the edb_audit_tag session parameter. If all database shared accounts are accessed via an application that uses the edb_audit_tag parameter to identify individual applications users, this is not a finding. 

If there are gaps in the application's ability to capture an individual user's identity, and the gaps and the risk are not defined in the system documentation and accepted by the AO, this is a finding.

If users are sharing a group account to log on to EDB Postgres tools or third-party products that access the database, this is a finding.

To ensure EDB auditing is enabled, execute the following SQL as enterprisedb:

 SHOW edb_audit;

If the result is not "csv" or "xml", this is a finding.)
  desc 'fix', 'Use accounts assigned to individual users where feasible. Configure the DBMS to provide individual accountability at the DBMS level, and in audit logs, for actions performed under a shared database account.

Modify any applications that use a shared database account to capture individual application user identities to the audit log using the edb_audit_tag or to the data tables.

Create and enforce the use of individual user IDs for logging on to EDB Postgres tools and third-party products.

If EDB auditing is not already enabled, enable it.

Execute the following SQL as enterprisedb:

 ALTER SYSTEM SET edb_audit = csv;
 SELECT pg_reload_conf();

or

 ALTER SYSTEM SET edb_audit = xml;
 SELECT pg_reload_conf();'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25806r495419_chk'
  tag severity: 'medium'
  tag gid: 'V-224133'
  tag rid: 'SV-224133r508023_rule'
  tag stig_id: 'EP11-00-000900'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-25794r495420_fix'
  tag 'documentable'
  tag legacy: ['SV-109397', 'V-100293']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
