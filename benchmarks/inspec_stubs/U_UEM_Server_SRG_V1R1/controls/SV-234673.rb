control 'SV-234673' do
  title 'The UEM server must authenticate endpoint devices (servers) before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk, such as remote connections.

This requires device-to-device authentication. Information systems must use IEEE 802.1x, Extensible Authentication Protocol [EAP], Radius server with EAP-Transport Layer Security [TLS] authentication, or Kerberos to identify/authenticate devices on local and/or wide area networks. 

Satisfies:FMT_SMF.1.1(2) b, FTP_ITC.1.1(1), FTP_ITC.1.2(1), FTP_ITC.1.3(1)  
Reference:PP-MDM-431009'
  desc 'check', 'Verify the UEM server authenticates endpoint devices (servers) before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.

If the UEM server does not authenticate endpoint devices (servers) before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the UEM server to authenticate endpoint devices (servers) before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37858r616025_chk'
  tag severity: 'medium'
  tag gid: 'V-234673'
  tag rid: 'SV-234673r617355_rule'
  tag stig_id: 'SRG-APP-000580-UEM-000398'
  tag gtitle: 'SRG-APP-000580'
  tag fix_id: 'F-37823r615654_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
