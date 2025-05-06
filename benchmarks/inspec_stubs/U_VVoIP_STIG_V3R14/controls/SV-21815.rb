control 'SV-21815' do
  title 'The Session Border Controller (SBC) must deny all packets traversing the enclave boundary (inbound or outbound) through the IP port pinholes opened for VVoIP sessions, except RTP/RTCP, SRTP/SRTCP, or other protocol/flow established by signaling messages.'
  desc 'Once a pinhole is opened in the enclave boundary for a known session, the packets that are permitted to pass must be managed. If they are not properly managed, packets that are not part of a known session may traverse a pinhole, giving unauthorized access to the enclave’s LAN or connected hosts. Another method for managing packets through a pinhole opened for a VVoIP session is to only permit packets to pass matching the expected protocol type, such as RTP/RTCP or SRTP/SRTCP. If only RTP/RTCP or SRTP/SRTCP packets are permitted to pass, this reduces the exposure presented to the enclave by the open pinhole.

Additional flows or protocols may be permitted if specifically required for an approved function and establishment is signaled or controlled by the signaling protocol in use by the system. An example of this is the transmission of H.281 far end camera control messages for a video conferencing session. Using AS-SIP for signaling, a UDP-based 6.4kbps H.224 over RTP control channel over which the H.281 far end camera control messages are transmitted might be established along with the media streams. This additional flow would require additional pinholes.'
  desc 'check', 'Verify the DISN NIPRnet boundary SBC is configured to deny all packets attempting to traverse the enclave boundary (inbound or outbound) through the IP port pinholes opened for VVoIP sessions that are not an approved protocol. The allowed protocols are RTP/RTCP, SRTP/SRTCP, and other approved protocols/flows established by signaling messages. This requires filtering on protocol type.

If the DISN NIPRnet boundary SBC does not deny all packets traversing the enclave boundary (inbound or outbound) through the IP port pinholes opened for VVoIP sessions, except approved protocols, this is a finding. 

If packets that are not RTP/RTCP or SRTP/SRTCP (or other approved packet type as established in the signaling messages) protocol packets can pass through the boundary SBC, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Configure the DISN NIPRnet boundary SBC to drop any packet attempting to traverse the enclave boundary (inbound or outbound) through the IP port pinholes opened for VVoIP sessions that is not a RTP/RTCP or SRTP/SRTCP packet or other approved protocol / flow established by the signaling messages.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.7
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24057r3_chk'
  tag severity: 'high'
  tag gid: 'V-19674'
  tag rid: 'SV-21815r4_rule'
  tag stig_id: 'VVoIP 6345'
  tag gtitle: 'VVoIP 6345'
  tag fix_id: 'F-20380r3_fix'
  tag 'documentable'
end
