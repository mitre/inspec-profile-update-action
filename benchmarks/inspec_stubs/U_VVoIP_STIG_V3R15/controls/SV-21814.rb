control 'SV-21814' do
  title 'The Session Border Controller (SBC) must perform stateful inspection and packet authentication for all VVoIP traffic (inbound and outbound), and deny all other packets.'
  desc 'Once a pinhole is opened in the enclave boundary for a known session, the packets that are permitted to pass must be managed. If they are not properly managed, packets that are not part of a known session could traverse the pinhole thereby giving unauthorized access to the enclave’s LAN or connected hosts.

One method for managing these packets is called stateful packet inspection. This inspection minimally validates that the permitted packets are part of a known session. This is a relatively weak but somewhat effective firewall function. A better method is to authenticate the source of the packet as coming from a known and authorized source.'
  desc 'check', 'Verify the DISN NIPRnet boundary SBC is configured to deny all packets attempting to traverse the enclave boundary (inbound or outbound) through the IP port pinholes opened for VVoIP sessions that are not validated as being part of an established session. This requires a stateful inspection of the packets passed through the IP port pinholes or the authentication of the source of those packets.

If packets that are not part of an established session can pass through the SBC, this is a finding. 

If stateful packet inspection or SRTP/SRTCP packet authentication is not configured, this is a finding. 

If stateful packet inspection is not configured but the source of the SRTP/SRTCP packets is authenticated from an authorized source, such as an internal endpoint or a remote DISN SBC, this is not a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Configure the DISN NIPRnet SBC to deny all packets attempting to traverse the enclave boundary (inbound or outbound) through the IP port pinholes opened for known sessions, except those validated as being part of an established session. This requires a stateful inspection of the packets passed through the IP port pinholes or the authentication of the source of those packets.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.7
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-69773r2_chk'
  tag severity: 'high'
  tag gid: 'V-19673'
  tag rid: 'SV-21814r4_rule'
  tag stig_id: 'VVoIP 6340'
  tag gtitle: 'VVoIP 6340'
  tag fix_id: 'F-20379r3_fix'
  tag 'documentable'
end
