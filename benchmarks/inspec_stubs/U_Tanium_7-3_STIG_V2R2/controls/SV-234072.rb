control 'SV-234072' do
  title 'The Tanium application database must be dedicated to only the Tanium application.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', "With the Tanium System Administrator's assistance, access the server on which the Tanium database(s) is installed.

Review the Tanium database(s).

If databases related to products other than Tanium exist in the Tanium database, this is a finding."
  desc 'fix', 'Move the Tanium database from the server hosting multiple databases for products other than Tanium or remove other product databases co-located with Tanium database(s).'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37257r610716_chk'
  tag severity: 'medium'
  tag gid: 'V-234072'
  tag rid: 'SV-234072r612749_rule'
  tag stig_id: 'TANS-DB-000002'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-37222r610717_fix'
  tag 'documentable'
  tag legacy: ['SV-102217', 'V-92115']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
