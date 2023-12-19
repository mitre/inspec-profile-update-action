control 'SV-50988' do
  title 'IIS must map client certificates to an approved certificate server'
  desc 'For EAS to be used effectively on DoD networks, client certificate authentication must be used for communications between the MEM and email server. Identification and Authentication provide the foundation for access control. IIS must be mapped to an approved certificate server for client certificates. Additionally, the internal and external URLs must be set to the same address, since all EAS traffic must be tunneled to the device from the MEM.

The risk associated with email syncronization with CMD should be mitigated by the introduction of MEM products and is specified in the DoD CIO memo dated 6 Apr 2011. The memo states specifically, "Email redirection from the email server (e.g., Exchange Server) to the device shall be controlled via centrally managed server." When EAS is used on DoD networks, the devices must be managed by an MEM.'
  desc 'check', 'Open a command window and enter the following commands:

CD C:\\Windows\\SysWOW64\\inetsrv
Appcmd.exe list config "Default Web Site/Microsoft-Server-ActiveSync" -section:clientCertificateMappingAuthentication

If clientCertificateMappingAuthentication enabled="true" is not returned, this is a finding.'
  desc 'fix', 'Open a command window and enter the following commands:

cd C:\\Windows\\SysWOW64\\InetSrv
appcmd unlock config /section:clientCertificateMappingAuthentication
appcmd set config "Default Web Site/Microsoft-Server-ActiveSync" -section:clientCertificateMappingAuthentication /enabled:true'
  impact 0.5
  ref 'DPMS Target Client Access Server'
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-46508r4_chk'
  tag severity: 'medium'
  tag gid: 'V-39172'
  tag rid: 'SV-50988r2_rule'
  tag stig_id: 'Exch-1-505'
  tag gtitle: 'Exch-1-505'
  tag fix_id: 'F-44149r2_fix'
  tag 'documentable'
end
