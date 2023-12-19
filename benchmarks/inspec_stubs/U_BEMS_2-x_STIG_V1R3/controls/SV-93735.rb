control 'SV-93735' do
  title 'If the Mail service (Push Notifications support for BlackBerry Work) is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to use Windows Authentication for the database connection.'
  desc 'To assure accountability and prevent unauthorized access, organizational users must be identified and authenticated. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'This requirement is not applicable if the Mail service (Push Notifications support for BlackBerry Work) is not enabled on BEMS.

Verify the mail service in BEMS is configured for Windows Authentication for the database connection as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
2. Click "Database".
3. In the "Server" field, type the Microsoft SQL Server host name and instance.
4. In the "Database" field, type the database name.
5. In the Windows Authentication drop-down list, verify "Windows Authentication" is selected.

If "Windows Authentication" is not selected for the mail service database connection, this is a finding.'
  desc 'fix', 'Set up Windows Authentication for the database connection for the mail service in BEMS:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail". 
2. Click "Database".
3. In the "Server" field, type the Microsoft SQL Server host name and instance.
4. In the "Database" field, type the database name.
5. In the Windows Authentication drop-down list, select "Windows Authentication".
6. Click "Save".'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79029'
  tag rid: 'SV-93735r1_rule'
  tag stig_id: 'BEMS-00-013800'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85779r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
