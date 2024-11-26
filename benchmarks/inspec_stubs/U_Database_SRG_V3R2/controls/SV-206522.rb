control 'SV-206522' do
  title 'The DBMS must protect against a user falsely repudiating having performed organization-defined actions.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account."
  desc 'check', 'Review system documentation to determine the data and the actions on data that need to be protected from repudiation by means of audit trails.

Review DBMS settings to determine whether users can be identified as individuals when using shared accounts. If the individual user who is using a shared account cannot be identified, this is a finding.

Review the design and the contents of the application data tables. If they do not include the necessary audit data, this is a finding.

Review the configuration of audit logs to determine whether auditing includes details identifying the individual user. If it does not, this is a finding.'
  desc 'fix', 'Use accounts assigned to individual users. Where the application connects to the DBMS using a standard, shared account, ensure that it also captures the individual user identification and passes it to the DBMS.

Modify application database tables and all supporting code to capture the necessary audit data.

Modify the configuration of audit logs to include details identifying the individual user.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6782r291234_chk'
  tag severity: 'medium'
  tag gid: 'V-206522'
  tag rid: 'SV-206522r617447_rule'
  tag stig_id: 'SRG-APP-000080-DB-000063'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-6782r291235_fix'
  tag 'documentable'
  tag legacy: ['SV-42684', 'V-32347']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
