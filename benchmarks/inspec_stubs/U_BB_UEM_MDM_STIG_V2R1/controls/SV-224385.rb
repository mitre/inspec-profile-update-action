control 'SV-224385' do
  title 'All BlackBerry UEM server local accounts created during application installation and configuration must be disabled or removed.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire BlackBerry UEM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the BlackBerry UEM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FMT_SMF.1.1(2) b / IA-5(1)(a)

'
  desc 'check', 'Review the BlackBerry UEM server configuration settings.

Verify the server is configured to leverage the MDM Platform user accounts and groups for BlackBerry UEM 12.11 server user identification and authentication.

On the BlackBerry UEM, do the following:
1. Navigate to the BlackBerry UEM console.
2. Verify the BlackBerry UEM does not prompt for additional authentication before opening the UEM console.

If the BlackBerry UEM server prompts for additional authentication before opening the UEM console, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM, do the following:

Configure constrained delegation for the Microsoft Active Directory account to support single sign-on:

1. Log in to the BlackBerry UEM 12.12 host server and use the Windows Server ADSI Edit tool to add the following SPNs for BES12 to the Microsoft Active Directory account:
- HTTP/<host_FQDN_or_pool_name> (for example, HTTP/domain123.example.com)
- BASPLUGIN111/<host_FQDN_or_pool_name> (for example, BASPLUGIN111/domain123.example.com)
 Note:
- If high availability is configured for the management consoles in a UEM domain, specify the pool name. Otherwise, specify the FQDN of the computer that hosts the management console.
- Verify that no other accounts in the Microsoft Active Directory forest have the same SPNs.
2. Open "Microsoft Active Directory Users and Computers".
3. In the Microsoft Active Directory account properties, on the "Delegation" tab, select the following options:
- Trust this user for delegation to specified services only.
- Use Kerberos only.
4. Add the SPNs from Step 1 to the list of services.

Configure single sign-on for UEM:
Note: 
- When configuring single sign-on for UEM, it is configured for the management console and UEM Self-Service.
- If enabling single sign-on for multiple Microsoft Active Directory connections, verify there are no trust relationships between the Microsoft Active Directory forests.
1. Log in to the BlackBerry UEM 12.12 console.
2. Select the "Settings" tab on the left pane.
3. Click the "External integration" tab on the left pane.
4. Click "Company directory".
5. In the "Configured directory connections" section, click the name of a Microsoft Active Directory connection.
6. On the "Authentication" tab, select the checkbox next to "Enable Windows single sign-on".
7. Click "Save".
8. Click "Save" on the pop-up window.
Note: UEM validates the information for Microsoft Active Directory authentication. If the information is invalid, UEM prompts to specify the correct information.
9. Click "Close".
10. Restart the UEM services on each server that hosts a UEM instance.'
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26062r539055_chk'
  tag severity: 'medium'
  tag gid: 'V-224385'
  tag rid: 'SV-224385r604136_rule'
  tag stig_id: 'BUEM-00-200040'
  tag gtitle: 'PP-MDM-431007'
  tag fix_id: 'F-26050r539056_fix'
  tag satisfies: ['SRG-APP-000148']
  tag 'documentable'
  tag legacy: ['SV-111887', 'V-102925']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
