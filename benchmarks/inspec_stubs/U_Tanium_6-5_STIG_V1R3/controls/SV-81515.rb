control 'SV-81515' do
  title 'The Tanium SQL server must be dedicated to the Tanium application database.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', "With the Tanium administrator's assistance, access the server on which the Tanium SQL database is installed.

Review the databases hosted by that SQL server.

If more databases exist on the SQL server than the Tanium database, this is a finding."
  desc 'fix', 'Move the Tanium SQL database from the SQL server hosting multiple databases to a dedicated SQL server or remove other databases co-located with Tanium on the existing SQL server.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67661r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67025'
  tag rid: 'SV-81515r1_rule'
  tag stig_id: 'TANS-DB-000002'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-73125r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
