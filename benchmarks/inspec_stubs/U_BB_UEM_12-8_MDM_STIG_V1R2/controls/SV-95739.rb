control 'SV-95739' do
  title 'The BlackBerry UEM 12.8 server must be configured to leverage the MDM platform user accounts and groups for MDM server user identification and authentication.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the BlackBerry UEM 12.8 server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', 'Review the BlackBerry UEM 12.8 server configuration settings, and verify the server is configured to leverage the MDM Platform user accounts and groups for BlackBerry UEM 12.8 server user identification and authentication.

On the BlackBerry UEM 12.8, do the following:
1. Navigate to the BlackBerry UEM 12.8 console.
2. Verify the BlackBerry UEM 12.8 does not prompt for additional authentication before opening the UEM console.

If the BlackBerry UEM 12.8 server prompts for additional authentication before opening the UEM console, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM 12.8, do the following:

Configure constrained delegation for the Microsoft Active Directory account to support single sign-on:

1. Log in to the BlackBerry UEM 12.8 host server and use the Windows Server ADSI Edit tool to add the following SPNs for BES12 to the Microsoft Active Directory account:
- HTTP/<host_FQDN_or_pool_name> (for example, HTTP/domain123.example.com)
- BASPLUGIN111/<host_FQDN_or_pool_name> (for example, BASPLUGIN111/domain123.example.com)
Note:
- If you configured high availability for the management consoles in a UEM domain, specify the pool name. Otherwise, specify the FQDN of the computer that hosts the management console.
- Verify that no other accounts in the Microsoft Active Directory forest have the same SPNs.
2. Open Microsoft Active Directory Users and Computers.
3. In the Microsoft Active Directory account properties, on the "Delegation" tab, select the following options:
- Trust this user for delegation to specified services only
- Use Kerberos only
4. Add the SPNs from step 1 to the list of services.

Configure single sign-on for UEM:
Note: 
- When you configure single sign-on for UEM, you configure it for the management console and UEM Self-Service.
- If you enable single sign-on for multiple Microsoft Active Directory connections, verify that there are no trust relationships between the Microsoft Active Directory forests.
1. Log in to the BlackBerry UEM 12.8 console and select the "Settings” tab at the left pane.
2. Click the "External integration" tab on the left pane.
3. Click "Company directory".
4. In the Configured directory connections section, click the name of a Microsoft Active Directory connection.
5. On the "Authentication" tab, select the check box next to "Enable Windows single sign-on".
6. Click "Save".
7. Click "Save" on popup window.
Note: UEM validates the information for Microsoft Active Directory authentication. If the information is invalid, UEM prompts you to specify the correct information.
8. Click "Close".
9. Restart the UEM services on each server that hosts a UEM instance.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Manager (UEM) 12.8'
  tag check_id: 'C-80743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81027'
  tag rid: 'SV-95739r1_rule'
  tag stig_id: 'BUEM-12-806700'
  tag gtitle: 'PP-MDM-314002'
  tag fix_id: 'F-87861r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002226', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)', 'AC-6 (5)']
end
