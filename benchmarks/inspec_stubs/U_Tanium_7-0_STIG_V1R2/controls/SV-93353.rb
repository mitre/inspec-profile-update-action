control 'SV-93353' do
  title 'The Tanium SQL server must be dedicated to the Tanium database.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', "With the Tanium System Administrator's assistance, access the server on which the Tanium SQL database is installed.

Review the databases hosted by that SQL server.

If more databases exist on the SQL server than the Tanium database, this is a finding."
  desc 'fix', 'Move the Tanium SQL database from the SQL server hosting multiple databases to a dedicated SQL server or remove other databases co-located with Tanium on the existing SQL server.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78217r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78647'
  tag rid: 'SV-93353r1_rule'
  tag stig_id: 'TANS-DB-000002'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-85383r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
