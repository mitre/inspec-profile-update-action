control 'SV-84351' do
  title 'Exchange must have IIS map client certificates to an approved certificate server.'
  desc 'For EAS to be used effectively on DoD networks, client certificate authentication must be used for communications between the MEM and email server. Identification and Authentication provide the foundation for access control. IIS must be mapped to an approved certificate server for client certificates. Additionally, the internal and external URLs must be set to the same address, since all EAS traffic must be tunneled to the device from the MEM.

The risk associated with email synchronization with CMD should be mitigated by the introduction of MEM products and is specified in the DoD CIO memo dated 06 Apr 2011. The memo states specifically, "Email redirection from the email server (e.g., Exchange Server) to the device shall be controlled via centrally managed server." When EAS is used on DoD networks, the devices must be managed by an MEM.'
  desc 'check', 'Open a command window and enter the following commands:

cd c:\\Windows\\SysWOW64\\inetsrv

Appcmd.exe list config "Default Web Site/Microsoft-Server-ActiveSync" -section:clientCertificateMappingAuthentication

If clientCertificateMappingAuthentication Enabled is not set to True, this is a finding.'
  desc 'fix', 'Open a command window and enter the following commands:

cd C:\\Windows\\SysWOW64\\InetSrv

appcmd unlock config /section:clientCertificateMappingAuthentication
appcmd set config "Default Web Site/Microsoft-Server-ActiveSync" -section:clientCertificateMappingAuthentication /enabled:true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70173r2_chk'
  tag severity: 'medium'
  tag gid: 'V-69729'
  tag rid: 'SV-84351r1_rule'
  tag stig_id: 'EX13-CA-000040'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-75935r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
