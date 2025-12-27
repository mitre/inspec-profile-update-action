control 'SV-254723' do
  title 'If the BlackBerry Connect service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to use Windows Authentication for the database connection.'
  desc 'To ensure accountability and prevent unauthorized access, organizational users must be identified and authenticated. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'This requirement is not applicable if the BlackBerry Connect service is not enabled on BEMS.

Verify the BlackBerry Connect service in BEMS is configured for Windows Authentication for the database connection as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Connect".
2. Click "Database".
3. In the "Database" field, type the database name.
4. In the "Windows Authentication" drop-down list, verify "Windows Authentication" is selected.

If "Windows Authentication" is not selected for the BlackBerry Connect database connection, this is a finding.'
  desc 'fix', 'Set up Windows Authentication for the database connection for the BlackBerry Connect service in BEMS:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Connect".
2. Click "Database".
3. In the "Database" field, type the database name.
4. In the "Windows Authentication" drop-down list, select "Windows Authentication".
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58334r861892_chk'
  tag severity: 'medium'
  tag gid: 'V-254723'
  tag rid: 'SV-254723r879887_rule'
  tag stig_id: 'BEMS-03-014200'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58280r861893_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
