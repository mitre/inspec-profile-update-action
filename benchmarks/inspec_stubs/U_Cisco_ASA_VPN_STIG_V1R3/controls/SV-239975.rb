control 'SV-239975' do
  title 'The Cisco ASA remote access VPN server must be configured to use TLS 1.2 or higher to protect the confidentiality of remote access connections.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

NIST SP 800-52 provides guidance for client negotiation on either DoD-only or public-facing servers.'
  desc 'check', 'Verify the TLS ASA is configured to use TLS 1.2 or higher as shown in the example below.

ssl server-version tlsv1.2 dtlsv1.2

Note: ASA supports TLS version 1.2 starting from software version 9.3.1 for secure message transmission for Clientless SSL VPN and AnyConnect VPN.

If the ASA is not configured to use TLS 1.2 or higher to protect the confidentiality of sensitive data during transmission, this is a finding.'
  desc 'fix', 'Configure the ASA to use TLS 1.2 or higher as shown in the example below.

ASA1(config)# ssl server-version tlsv1.2 dtlsv1.2'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43208r666329_chk'
  tag severity: 'high'
  tag gid: 'V-239975'
  tag rid: 'SV-239975r666331_rule'
  tag stig_id: 'CASA-VN-000550'
  tag gtitle: 'SRG-NET-000062-VPN-000200'
  tag fix_id: 'F-43167r666330_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
