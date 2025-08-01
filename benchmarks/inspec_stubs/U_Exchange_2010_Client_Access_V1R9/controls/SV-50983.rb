control 'SV-50983' do
  title 'Exchange ActiveSync (EAS) must only use certificate-based authentication to access email.'
  desc 'Identification and Authentication provide the foundation for access control. For EAS to be used effectively on DoD networks, client certificate authentication must be used for communications between the MEM and email server. Additionally, the internal and external URLs must be set to the same address, since all EAS traffic must be tunneled to the device from the MEM.

The risk associated with email synchronization with CMD should be mitigated by the introduction of MEM products and is specified in the DoD CIO memo dated 6 Apr 2011. The memo states specifically, "Email redirection from the email server (e.g., Exchange Server) to the device shall be controlled via centrally managed server." When EAS is used on DoD networks, the devices must be managed by an MEM.'
  desc 'check', 'Open the Exchange Management Shell and enter the following commands:

Get-ActiveSyncVirtualDirectory -Identity "<Identity Name>\\Microsoft-Server-ActiveSync (Default Web Site)" | fl Basic
AuthEnabled,WindowsAuthEnabled,ClientCertAuth,WebSiteSSLEnabled,InternalAuthenticationMethods,ExternalAuthenticationMethods

These should be the results returned:

BasicAuthEnabled :  False
WindowsAuthEnabled :  False
ClientCertAuth :  Required
WebSiteSSLEnabled :  True
InternalAuthenticationMethods :  {Certificate}
ExternalAuthenticationMethods :  {Certificate}

If the values above are not returned, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ActiveSyncVirtualDirectory -Identity "ClientAccessServerName\\Microsoft-Server-ActiveSync (Default Web Site)" -ClientCertAuth "Required" -WindowsAuthEnabled:$False -InternalAuthenticationMethods "Certificate" –ExternalAuthenticationMethods “Certificate” –ExternalUrl “https://mail-site.easf.csd.disa.mil/Microsoft-Server-ActiveSync”'
  impact 0.5
  ref 'DPMS Target Client Access Server'
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-46507r4_chk'
  tag severity: 'medium'
  tag gid: 'V-39167'
  tag rid: 'SV-50983r2_rule'
  tag stig_id: 'Exch-1-502'
  tag gtitle: 'Exch-1-502'
  tag fix_id: 'F-44146r2_fix'
  tag 'documentable'
end
