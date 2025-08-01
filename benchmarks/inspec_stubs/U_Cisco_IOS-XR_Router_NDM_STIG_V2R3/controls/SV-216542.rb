control 'SV-216542' do
  title 'The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the router configuration to verify that SSH version 2 is configured as shown in the example below.

ssh server v2

Note: IOS XR supports SSHv1 and SSHv2. The AES encryption algorithm is supported on the SSHv2 server and client, but not on the SSHv1 server and client. Any requests for an AES cipher sent by an SSHv2 client to an SSHv1 server are ignored, with the server using 3DES instead. The cipher preference for the SSH server follows the order AES128, AES192, AES256, and, finally, 3DES. The server rejects any requests by the client for an unsupported cipher, and the SSH session does not proceed.

If the router is configured to implement SSH version 1, this is a finding.'
  desc 'fix', 'Configure the router to use SSH version 2 as shown in the example below.

RP/0/0/CPU0:R3(config)#ssh server v2'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17777r288312_chk'
  tag severity: 'high'
  tag gid: 'V-216542'
  tag rid: 'SV-216542r879785_rule'
  tag stig_id: 'CISC-ND-001210'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-17774r288313_fix'
  tag 'documentable'
  tag legacy: ['SV-105613', 'V-96475']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
