control 'SV-44008' do
  title 'Forms-based Authentication must not be enabled.'
  desc 'Identification and Authentication provide the foundation for access control.  Access to email services applications in the DoD require authentication using DoD Public Key Infrastructure (PKI) certificates.  Authentication for Outlook Web App (OWA) is used to enable web access to user email mailboxes and should assume that certificate-based authentication has been configured.  This setting controls whether forms-based login should be used by the OWA web site. 

Because the DoD requires Common Access Card (CAC)-based authentication to applications, OWA access must be brokered through an application proxy or other pre-authenticator, which performs CAC authentication prior to arrival at the CA server.  The authenticated request is then forwarded directly to OWA, where authentication is repeated without requiring the user to repeat authentication steps.  For this scenario to work, the Application Proxy server must have forms-based authentication enabled, and Exchange must have forms-based Authentication disabled.  

If forms-based Authentication is enabled on the Exchange CA server, it is evidence that the application proxy server is either not correctly configured, or it may be missing.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-OwaVirtualDirectory | Select Name, Identity, FormsAuthentication

If the value of 'FormsAuthentication' is not set to 'False', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-OwaVirtualDirectory -Identity <'IdentityName'> -FormsAuthentication $false"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33588'
  tag rid: 'SV-44008r1_rule'
  tag stig_id: 'Exch-1-205'
  tag gtitle: 'Exch-1-205'
  tag fix_id: 'F-37479r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
