control 'SV-253833' do
  title 'The Tanium application database must be dedicated to only the Tanium application.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example, limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', "With the Tanium system administrator's assistance, access the server on which the Tanium database(s) is installed. 

1. Access the Tanium Server.

2. Log on to each Tanium Application Server with an account that has administrative privileges.

3. Verify SQL Server Services are not running on both servers. 

If SQL Server Services are running on either server, this is a finding. 

Review the Tanium database(s). If databases related to products other than Tanium exist in the Tanium database, this is a finding."
  desc 'fix', 'Move the Tanium database from the server hosting multiple databases for products other than Tanium or remove other product databases co-located with Tanium database(s).'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57285r842525_chk'
  tag severity: 'medium'
  tag gid: 'V-253833'
  tag rid: 'SV-253833r850162_rule'
  tag stig_id: 'TANS-DB-000002'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-57236r842526_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
