control 'SV-242575' do
  title 'The Cisco ISE must use TLS 1.2, at a minimum, to protect the confidentiality of information passed between the endpoint agent and the Cisco ISE for the purposes of client posture assessment.'
  desc 'The agent may pass information about the endpoint to the Cisco ISE, which may be sensitive. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.'
  desc 'check', 'Verify that only TLS 1.2 is enabled. 

From the Web Admin portal: 
1. Navigate to Administration >> System >> Settings >> Security Settings.
2. Ensure "Allow TLS1.0", "Allow TLS1.1", and "Allow legacy unsafe TLS renegotiation for ISE as a client" are unchecked. 

If TLS 1.0 or 1.1 is enabled, this is a finding.'
  desc 'fix', 'Configure ISE so that only TLS 1.2 is enabled: 

From the Web Admin portal:
1. Navigate to Administration >> System >> Settings >> Security Settings.
2. Ensure "Allow TLS1.0", "Allow TLS1.1", and "Allow legacy unsafe TLS renegotiation for ISE as a client" are unchecked.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45850r714033_chk'
  tag severity: 'high'
  tag gid: 'V-242575'
  tag rid: 'SV-242575r714035_rule'
  tag stig_id: 'CSCO-NC-000010'
  tag gtitle: 'SRG-NET-000062-NAC-000340'
  tag fix_id: 'F-45807r714034_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
