control 'SV-254727' do
  title 'If the BlackBerry Docs service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to use SSL for LDAP lookup to connect to the Office Web App Server (e.g., SharePoint).'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS) or SSL.'
  desc 'check', 'This requirement is not applicable if the BlackBerry Docs service is not enabled on BEMS.

Verify the BlackBerry Docs service is configured to use SSL for LDAP Lookup to connect to the Office Web App Server (e.g., SharePoint) as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Docs".
2. Click "Settings".
3. Verify "Use SSL for LDAP" is selected.

If SSL for LDAP is not enabled for the BlackBerry Docs service, this is a finding.'
  desc 'fix', 'This requirement is not applicable if the BlackBerry Docs service is not enabled on BEMS.

Configure the BlackBerry Docs service to use SSL for LDAP Lookup to connect to the Office Web App Server (e.g., SharePoint) as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Docs". 
2. Click "Settings".
3. Select the "Enable Kerberos Constrained Delegation" check box to allow Docs to use Kerberos constrained delegation.
4. Enter each of the Microsoft SharePoint Online domains that will be made available.
5. Enter the URL for the approved Office Web App Server.
6. Provide the Microsoft Active Directory user domains (separated by commas) and then enter the corresponding LDAP Port. 
7. Select the "Use SSL for LDAP" check box.
8. Click "Save".'
  impact 0.7
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58338r861904_chk'
  tag severity: 'high'
  tag gid: 'V-254727'
  tag rid: 'SV-254727r861906_rule'
  tag stig_id: 'BEMS-03-014600'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58284r861905_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
