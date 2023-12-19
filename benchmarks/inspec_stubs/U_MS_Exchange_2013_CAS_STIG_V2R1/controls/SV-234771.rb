control 'SV-234771' do
  title 'Exchange ActiveSync (EAS) must only use certificate-based authentication to access email.'
  desc 'Identification and Authentication provide the foundation for access control. For EAS to be used effectively on DoD networks, client certificate authentication must be used for communications between the MEM and email server. Additionally, the internal and external URLs must be set to the same address, since all EAS traffic must be tunneled to the device from the MEM.

The risk associated with email synchronization with CMD should be mitigated by the introduction of MEM products and is specified in the DoD CIO memo dated 06 Apr 2011. The memo states specifically, "Email redirection from the email server (e.g., Exchange Server) to the device shall be controlled via centrally managed server." When EAS is used on DoD networks, the devices must be managed by an MEM.'
  desc 'check', "Open the Exchange Management Shell and enter the following commands:

Get-ActiveSyncVirtualDirectory | Select Name, Identity

Get-ActiveSyncVirtualDirectory -Identity '<ServerName>Microsoft-Server-ActiveSync (Default Web Site)' | fl BasicAuthEnabled, WindowsAuthEnabled, ClientCertAuth, WebSiteSSLEnabled, InternalAuthenticationMethods, ExternalAuthenticationMethods

Note: The <ServerName>Microsoft-Server-ActiveSync (Default Web Site) value must be in quotes.

The command should return the following: 

BasicAuthEnabled :  False
WindowsAuthEnabled :  False
ClientCertAuth :  Required
WebSiteSSLEnabled :  True
InternalAuthenticationMethods :  {Certificate}
ExternalAuthenticationMethods :  {Certificate}

If the values above are not returned, this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ActiveSyncVirtualDirectory -Identity ‘<ServerName>\\Microsoft-Server-ActiveSync (Default Web Site)’ -BasicAuthEnabled $False -WindowsAuthEnabled $False -ClientCertAuth ‘Required’ -WebSites-InternalAuthenticationMethods ‘Certificate’ -ExternalAuthenticationMethods ‘Certificate’

Note: The <ServerName>Microsoft-Server-ActiveSync (Default Web Site) value must be in quotes.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37957r617252_chk'
  tag severity: 'medium'
  tag gid: 'V-234771'
  tag rid: 'SV-234771r617254_rule'
  tag stig_id: 'EX13-CA-000035'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-37920r617253_fix'
  tag 'documentable'
  tag legacy: ['SV-84349', 'V-69727']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
