control 'SV-252627' do
  title 'The IBM Aspera High-Speed Transfer Server must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol thus are in scope for this requirement. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Verify IBM Aspera High-Speed Transfer Server only uses TLS 1.2 or greater with the following command:

$ sudo /opt/aspera/bin/asuserdata -a | grep ssl_protocol
 ssl_protocol: "tlsv1.2" 
 ssl_protocol: "tlsv1.2" 

If both entries do not return "tlsv1.2" or greater , this is a finding.'
  desc 'fix', 'Configure the IBM Aspera High-Speed Transfer Server SSL security protocol to TLS version 1.2 or higher:

$ sudo /opt/aspera/bin/asconfigurator -x "set_server_data;ssl_protocol,tlsv1.2"

$ sudo /opt/aspera/bin/asconfigurator -x "set_client_data;ssl_protocol,tlsv1.2"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.7
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56083r818049_chk'
  tag severity: 'high'
  tag gid: 'V-252627'
  tag rid: 'SV-252627r818051_rule'
  tag stig_id: 'ASP4-TS-020100'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-56033r818050_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
