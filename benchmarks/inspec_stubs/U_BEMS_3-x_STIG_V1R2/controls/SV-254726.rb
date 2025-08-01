control 'SV-254726' do
  title 'If the BlackBerry Docs service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to use NTLM authentication.'
  desc 'To ensure accountability and prevent unauthorized access, organizational users must be identified and authenticated. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'This requirement is not applicable if the BlackBerry Docs service is not enabled on BEMS.

Verify NTLM authentication is enabled for the BlackBerry Docs service as follows:

1. In the BEMS Dashboard, under "Good Services Configuration", click "Docs".
2. Click "Web Proxy".
3. Select "Use Web Proxy".
4. In the Proxy Server Authentication Type drop-down list, verify "NTLM authentication" is selected.

If NTLM authentication is not enabled for the BlackBerry Docs service, this is a finding.'
  desc 'fix', 'Configure NTLM authentication for the BlackBerry Docs service as follows:

1. In the BEMS Dashboard, under "Good Services Configuration", click "Docs".
2. Click "Web Proxy".
3. Select the "Use Web Proxy".
4. In the Proxy Server Authentication Type drop-down list, select "NTLM authentication".
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58337r861901_chk'
  tag severity: 'medium'
  tag gid: 'V-254726'
  tag rid: 'SV-254726r879887_rule'
  tag stig_id: 'BEMS-03-014500'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58283r861902_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
