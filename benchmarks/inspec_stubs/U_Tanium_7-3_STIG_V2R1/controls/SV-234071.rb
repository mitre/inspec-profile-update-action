control 'SV-234071' do
  title 'The Tanium database(s) must be installed on a separate system.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries, limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases, and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the server to which the database has been installed and is configured.

If the customer is using a Tanium Appliance, this is Not Applicable.

If the database is installed on the same server as the Tanium Server or Tanium Module Server, this is a finding.'
  desc 'fix', 'Move the Tanium database from the Tanium Server or Tanium Module Server to a separate server.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37256r610713_chk'
  tag severity: 'medium'
  tag gid: 'V-234071'
  tag rid: 'SV-234071r612749_rule'
  tag stig_id: 'TANS-DB-000001'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-37221r610714_fix'
  tag 'documentable'
  tag legacy: ['SV-102215', 'V-92113']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
