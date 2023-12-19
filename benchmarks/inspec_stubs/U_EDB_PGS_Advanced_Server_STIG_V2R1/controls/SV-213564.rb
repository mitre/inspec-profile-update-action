control 'SV-213564' do
  title 'The EDB Postgres Advanced Server must protect against a user falsely repudiating having performed organization-defined actions.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables, and configuring the DBMS' audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, group account."
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW edb_audit;
 
If the result is not "csv" or "xml", this is a finding.'
  desc 'fix', 'Execute the following SQL as enterprisedb:

ALTER SYSTEM SET edb_audit = csv;
SELECT pg_reload_conf();

or

ALTER SYSTEM SET edb_audit = xml;
SELECT pg_reload_conf();'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14786r290004_chk'
  tag severity: 'medium'
  tag gid: 'V-213564'
  tag rid: 'SV-213564r508024_rule'
  tag stig_id: 'PPS9-00-000900'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-14784r290005_fix'
  tag 'documentable'
  tag legacy: ['V-68881', 'SV-83485']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
