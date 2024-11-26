control 'SV-253832' do
  title 'The Tanium database(s) must be installed on a separate system.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example, limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', 'Note: If the customer is using a Tanium Appliance, this is not applicable.

Consult with the Tanium system administrator to determine the server to which the database has been installed and is configured. 

1. Access the Tanium Server.

2. Log on to each Tanium Application Server with an account that has administrative privileges.

3. Verify Tanium Module Service is not running on both servers. 

4. Verify SQL Server Services are not running on both servers. 

If the Tanium Module Service is running on either server, this is a finding.

If SQL Server Services are running on either server, this is a finding. 

If the database is installed on the same server as the Tanium Server or Tanium Module Server, this is a finding.'
  desc 'fix', 'Move the Tanium database from the Tanium Server or Tanium Module Server to a separate server. Steps to move the Tanium database can be found at https://docs.tanium.com/platform_install/platform_install/installing_tanium_server.html#set_up_DB_server.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57284r842522_chk'
  tag severity: 'medium'
  tag gid: 'V-253832'
  tag rid: 'SV-253832r850162_rule'
  tag stig_id: 'TANS-DB-000001'
  tag gtitle: 'SRG-APP-000323'
  tag fix_id: 'F-57235r842523_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
