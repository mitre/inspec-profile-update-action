control 'SV-228417' do
  title 'Exchange must have forms-based authentication disabled.'
  desc 'Identification and Authentication provide the foundation for access control. Access to email services applications in the DoD requires authentication using DoD Public Key Infrastructure (PKI) certificates. Authentication for Outlook Web App (OWA) is used to enable web access to user email mailboxes and should assume that certificate-based authentication has been configured. This setting controls whether forms-based logon should be used by the OWA website. 

Because the DoD requires Common Access Card (CAC)-based authentication to applications, OWA access must be brokered through an application proxy or other pre-authenticator, which performs CAC authentication prior to arrival at the CA server. The authenticated request is then forwarded directly to OWA, where authentication is repeated without requiring the user to repeat authentication steps. For this scenario to work, the Application Proxy server must have forms-based authentication enabled, and Exchange must have forms-based Authentication disabled. 

If forms-based Authentication is enabled on the Exchange CA server, it is evidence that the application proxy server is either not correctly configured, or it may be missing.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-OwaVirtualDirectory | Select ServerName, Name, Identity, FormsAuthentication

If the value of "FormsAuthentication" is not set to "False", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-OwaVirtualDirectory -Identity <'IdentityName'> -FormsAuthentication $false

Note: <IdentityName> must be in single quotes.

Example for the Identity Name: <ServerName>\\owa (Default website)

Restart the ISS service."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30650r497047_chk'
  tag severity: 'medium'
  tag gid: 'V-228417'
  tag rid: 'SV-228417r879519_rule'
  tag stig_id: 'EX16-MB-002920'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-30635r497048_fix'
  tag 'documentable'
  tag legacy: ['SV-95429', 'V-80719']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
