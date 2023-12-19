control 'SV-235102' do
  title 'The MySQL Database Server 8.0 must protect against a user falsely repudiating having performed organization-defined actions.'
  desc 'Non-repudiation of actions taken is required to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables, and configuring DBMS audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, group account.'
  desc 'check', 'Obtain the list of authorized MySQL Server accounts in the system documentation.  

Determine if any accounts are shared. A shared account is defined as a username, hostname, and password that are used by multiple individuals to log in to SQL Server. An example of a shared account is the MySQL Server root account – root@localhost.

If accounts are determined to be shared, determine if individuals are first individually authenticated.  

If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding.  

The key is individual accountability. If this can be traced, this is not a finding.

If accounts are determined to be shared, determine if they are directly accessible to end users. If so, this is a finding.

Review contents of audit logs, traces, and data tables to confirm the identity of the individual user performing the action is captured.

If shared identifiers are found, and not accompanied by individual identifiers, this is a finding.

Note: Privileged installation accounts like root@localhost may be required to be accessed by the DBA or other administrators for system maintenance. In these cases, each use of the account must be logged in some manner to assign accountability for any actions taken during the use of the account.'
  desc 'fix', "Remove user-accessible shared accounts and use individual user IDs.

Build/configure applications to ensure successful individual authentication prior to shared account access.

Ensure each user's identity is received and used in audit data in all relevant circumstances.

Design, develop, and implement a method to log use of any account to which more than one person has access. Restrict interactive access to shared accounts to the fewest persons possible."
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38321r623426_chk'
  tag severity: 'medium'
  tag gid: 'V-235102'
  tag rid: 'SV-235102r638812_rule'
  tag stig_id: 'MYS8-00-001500'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-38284r623427_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
