control 'SV-93351' do
  title 'The Tanium SQL database must be installed on a separate system.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the server to which the SQL database has been installed and is configured.

If the SQL database is installed on the same server as the Tanium Server, this is a finding.'
  desc 'fix', 'Move the Tanium SQL database from the Tanium Server to a separate SQL server system.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78215r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78645'
  tag rid: 'SV-93351r1_rule'
  tag stig_id: 'TANS-DB-000001'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-85381r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
