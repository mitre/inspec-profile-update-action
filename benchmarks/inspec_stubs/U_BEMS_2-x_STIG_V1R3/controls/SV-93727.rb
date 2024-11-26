control 'SV-93727' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must be configured to use Windows Authentication for the database connection.'
  desc 'To assure accountability and prevent unauthorized access, organizational users must be identified and authenticated. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'Verify BEMS is configured for Windows Authentication for the database connection as follows:

In the Database Information dialog box, verify "Windows Authentication" is selected. 

If "Windows Authentication" is not selected for the BEMS database connection, this is a finding.'
  desc 'fix', 'Set up Windows Authentication for the database connection on the BEMS console. In the Database Information dialog box, perform the following actions:

1. In the "Host" field, type the instance name of your SQL Server.
2. In the "Database" name field, type the name for the BEMS-Core database.
3. In the "Port" field, type the port number that connects to the SQL Server.
4. Select "Windows Authentication".
5. Click "Next".'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78609r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79021'
  tag rid: 'SV-93727r1_rule'
  tag stig_id: 'BEMS-00-013400'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85771r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
