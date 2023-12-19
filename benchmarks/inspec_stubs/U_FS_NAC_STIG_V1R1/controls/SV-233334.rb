control 'SV-233334' do
  title 'Communications between Forescout endpoint agent and the switch must transmit access authorization information via a protected path using a cryptographic mechanism.'
  desc 'Forescout solution assesses the compliance posture of each client and returns an access decision based on configured security policy. The communications associated with this traffic must be protected from alteration and spoofing attacks so unauthorized devices do not gain access to the network.'
  desc 'check', 'Verify both ends are configured for secure communications between the NAC and NAC agent.

If communication between the NAC and NAC agent does not use an encrypted method for protecting posture information transmitted between the devices, this is a finding.'
  desc 'fix', 'Log on to the Forescout UI.

1. Select Tools >> Option >> HPS Inspection Engine >> SecureConnector.
2. In the Client-Server Connection, check the Minimum Supported TLS Version is set to TLS version 1.2.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36529r605705_chk'
  tag severity: 'medium'
  tag gid: 'V-233334'
  tag rid: 'SV-233334r611394_rule'
  tag stig_id: 'FORE-NC-000290'
  tag gtitle: 'SRG-NET-000320-NAC-001200'
  tag fix_id: 'F-36494r605706_fix'
  tag 'documentable'
  tag cci: ['CCI-002353']
  tag nist: ['AC-24 (1)']
end
