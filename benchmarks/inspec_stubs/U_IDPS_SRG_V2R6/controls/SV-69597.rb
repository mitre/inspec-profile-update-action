control 'SV-69597' do
  title 'The IDPS must, for fragmented packets, either block the packets or properly reassemble the packets before inspecting and forwarding.'
  desc 'Packet fragmentation is allowed by the TCP/IP specifications and is encouraged in situations where it is needed. However, packet fragmentation has been used to make some attacks harder to detect (by placing them within fragmented packets), and unusual fragmentation has also been used as a form of attack. For example, some network-based attacks have used packets that should not exist in normal communications, such as sending some fragments of a packet but not the first fragment, or sending packet fragments that overlap each other. These, and other types of packet fragmentation, aim to evade the IDPS. 

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Verify the IDPS, for fragmented packets, either blocks the packets or properly reassembles the packets before inspecting and forwarding.

For fragmented packets, if the IDPS does not either block the packets or properly reassemble the packets before inspecting and forwarding, this is a finding.'
  desc 'fix', 'Configure the IDPS to, for fragmented packets, either block the packets or properly reassemble the packets before inspecting and forwarding.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55975r2_chk'
  tag severity: 'medium'
  tag gid: 'V-55351'
  tag rid: 'SV-69597r1_rule'
  tag stig_id: 'SRG-NET-000401-IDPS-00203'
  tag gtitle: 'SRG-NET-000401-IDPS-00203'
  tag fix_id: 'F-60219r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
