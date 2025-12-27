control 'SV-254720' do
  title 'If the Mail service (Push Notifications support for BlackBerry Work) is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to use Windows Integrated Authentication for the Exchange connection.'
  desc 'To ensure accountability and prevent unauthorized access, organizational users must be identified and authenticated. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'This requirement is not applicable if the Mail service (Push Notifications support for BlackBerry Work) is not enabled on BEMS.

Verify Windows Integrated Authentication for the Exchange connection for the Mail service has been set up in BEMS as follows:

*On-Prem email server used at site:
1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
2. Click "Microsoft Exchange".
3. Under "Enter Service Account Details", verify "Use Windows Integrated Authentication" has been selected.

*O-365 email server used at site:
1. If credential authentication is used by the site:
     a. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
     b. Click "Microsoft Exchange".
     c. In the "Select Authentication type" section, verify "Credential" authentication type is listed.
2. If client certificate is used at site:
     a. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
     b. Click "Microsoft Exchange".
     c. In the "Select Authentication type" section, verify "Client Certificate" authentication type is listed.

If Windows Integrated Authentication for the Exchange connection for the Mail service has not been set up in BEMS, this is a finding.'
  desc 'fix', 'Set up Windows Integrated Authentication for the Exchange connection for the Mail service in BEMS:

*On-Prem email server used at site:
1. Log on to BEMS with the service account that will be configured.
2. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
3. Click "Microsoft Exchange".
4. Under "Enter Service Account Details", select the "Use Windows Integrated Authentication" check box.
5. Click "Save".

*O-365 email server used at site: 
Use one of the following procedures based on the authentication type used at the site.
1. Credential 
     a. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
     b. Click "Microsoft Exchange".
     c. In the "Select Authentication type" section, select "Credential" authentication type and complete the associated task to allow BEMS to communicate with Microsoft O365. (This option uses a defined BEMS username and password to authenticate to Microsoft Office 365 using Basic Authentication.)
         i. In the "Username" field, enter the User Principal Name (UPN) of the BEMS service account.
         ii. In the "Password" field, enter the password for the service account. 
2. Client Certificate 
     a. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Mail".
     b. Click "Microsoft Exchange".
     c. In the "Select Authentication type" section, select "Client Certificate" authentication type and complete the associated task to allow BEMS to communicate with Microsoft O365. (This option uses a client certificate to allow the BEMS service account to authenticate to Microsoft Office 365.)
         i. For the "Upload PFX file", click "Choose File" and select the client certificate file.
         ii. In the "Enter PFX file Password" field, enter the password for the client certificate.'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58331r916410_chk'
  tag severity: 'medium'
  tag gid: 'V-254720'
  tag rid: 'SV-254720r916412_rule'
  tag stig_id: 'BEMS-03-013900'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58277r916411_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
