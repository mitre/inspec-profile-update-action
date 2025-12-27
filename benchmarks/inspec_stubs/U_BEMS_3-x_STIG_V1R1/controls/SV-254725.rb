control 'SV-254725' do
  title 'If the BlackBerry Docs service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to use Windows Authentication for the database connection.'
  desc 'To ensure accountability and prevent unauthorized access, organizational users must be identified and authenticated. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'This requirement is not applicable if the BlackBerry Docs service is not enabled on BEMS.

Verify the BlackBerry Docs service in BEMS is configured for Windows Authentication for the database connection as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Docs".
2. Click "Database".
3. In the "Database" field, type the database name.
4. In the Windows Authentication drop-down list, verify "Windows Authentication" is selected.

If "Windows Authentication" is not selected for the BlackBerry Docs database connection, this is a finding.'
  desc 'fix', 'Set up Windows Authentication for the database connection for the BlackBerry Docs service in BEMS:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Docs".
2. Click "Database".
3. In the "Database" field, type the database name.
4. In the Windows Authentication drop-down list, select "Windows Authentication".
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58336r861898_chk'
  tag severity: 'medium'
  tag gid: 'V-254725'
  tag rid: 'SV-254725r861900_rule'
  tag stig_id: 'BEMS-03-014400'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58282r861899_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
