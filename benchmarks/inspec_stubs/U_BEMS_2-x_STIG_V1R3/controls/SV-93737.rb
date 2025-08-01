control 'SV-93737' do
  title 'If the Mail service (Push Notifications support for BlackBerry Work) is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to use Windows Integrated Authentication for the Exchange connection.'
  desc 'To assure accountability and prevent unauthorized access, organizational users must be identified and authenticated. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'This requirement is not applicable if the Mail service (Push Notifications support for BlackBerry Work) is not enabled on BEMS.

Verify Windows Integrated Authentication for the Exchange connection for the Mail service has been set up in BEMS as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
2. Click "Microsoft Exchange".
3. Under "Enter Service Account Details", verify "Use Windows Integrated Authentication" has been selected.

If Windows Integrated Authentication for the Exchange connection for the Mail service has not been set up in BEMS, this is a finding.'
  desc 'fix', 'Set up Windows Integrated Authentication for the Exchange connection for the Mail service in BEMS:

1. Log on to BEMS with the service account that will be configured.
2. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
3. Click "Microsoft Exchange".
4. Under "Enter Service Account Details", select the "Use Windows Integrated Authentication" check box.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79031'
  tag rid: 'SV-93737r1_rule'
  tag stig_id: 'BEMS-00-013900'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85781r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
