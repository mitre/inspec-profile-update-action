control 'SV-8736' do
  title 'DoD-to-DoD VVoIP traffic traversing any publicly accessible wide area network (i.e., Internet, NIPRnet) must use FIPS-validated encryption for unclassified traffic or NSA-approved encryption for classified traffic.'
  desc 'When VVoIP connections are established across a publicly accessible WAN, all communications confidentiality and integrity can be lost. Information gleaned from signaling messages can be used to attack the system or for other nefarious reasons. If VVoIP traffic is passed in the clear it is open to sniffing attacks. This vulnerability exists whether the traffic is on a LAN/CAN or a MAN/WAN. Native end-to-end encryption of the signaling and media mitigates this vulnerability. As a secondary solution, mitigation can be accomplished at the link level through the incorporation of encrypted VPN tunneling technology. Both solutions are applicable when the communicating endpoints are operated by the same organization or they reside in enclaves operated by the same organization and the endpoints and supporting systems are interoperable. As such, encryption of some approved form is required to protect DoD-to-DoD communications across a public network such as the Internet or a publicly accessible network such as the NIPRnet.

While end-to-end application or protocol-level encryption is preferred, tunneling unencrypted VVOIP signaling and media traffic using FIPS-validated site-to-site or client-to-site (remote access) VPN technologies mitigates the risk. The inherent NSA-approved site-to-site encryption employed for classified networks, such as the SIPRnet, also meets this requirement, although such networks are not public or publicly accessible as a rule.

DoD-to-DoD voice communications are generally considered to contain sensitive information. Local DoD enclaves connect to a DISN SDN via an access circuit. Unless the site is a host to an SDN, or close enough to it to be served by DoD-owned facilities, some portion of the access circuit will use leased commercial facilities. Additionally, the DISN core network itself may traverse commercial services and facilities. Therefore, DoD voice and data traffic crossing the unclassified DISN must be encrypted.'
  desc 'check', 'Review site documentation to confirm all DoD-to-DoD VVOIP signaling and media traffic traversing a public or publicly accessible WAN (i.e., Internet, NIPRnet) is encrypted, natively at the application or protocol level, or using network or data-link layer encryption (i.e., encrypted VPN or bulk link encryption) using FIPS-validated encryption for unclassified traffic or NSA-approved encryption for classified traffic. Otherwise this is a finding.

NOTE: This requirement is applicable to the following: 
- Calls established between DoD endpoints within an extended enclave (single MILDEP organization using directly interoperable VoIP systems). 
- Calls established between DoD endpoints located in different enclaves operated by a single MILDEP organization using directly interoperable VoIP systems. 
- Calls established between DoD endpoints located in different enclaves operated by different MILDEP organizations whether using directly interoperable VoIP systems and endpoints or the systems are subscribers to the DISN IPVS using IPVS standard protocols. 
- Calls established between remote DoD endpoints located outside their home enclave and connecting across the Internet and/or NIPRnet. In this case, a remote access VPN is used. 

NOTE: At this time, this requirement is not applicable for calls established from DoD to commercial VoIP telephones via commercial ITSP services implemented as a replacement for TDM-based PSTN access. This is because there is no encryption standard for end-to-end VoIP sessions to which all ITSPs and phone vendors have subscribed. Once a universal standard is adopted and implemented, or translation gateways are developed, this requirement could then be applied. Before encryption standards are adopted, the world must adopt interoperable signaling and media standards. At this time, Session Border Controllers can provide some translation services. Additional considerations are discussed in the section on ITSP services.'
  desc 'fix', 'Implement all DoD-to-DoD VVOIP signaling and media traffic traversing a public or publicly accessible WAN network (i.e., Internet, NIPRnet) to use FIPS-validated encryption for unclassified traffic or NSA-approved encryption for classified traffic, either natively at the application or protocol level, or by using network or data-link layer encryption (i.e., encrypted VPN or bulk link encryption). 

The encryption of VVOIP signaling and media traffic may either use native end-to-end basis or tunnel it using site-to-site or client-to-site (remote access) VPN technologies or bulk link encryption.'
  impact 0.7
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23685r4_chk'
  tag severity: 'high'
  tag gid: 'V-8250'
  tag rid: 'SV-8736r4_rule'
  tag stig_id: 'VVoIP 1400'
  tag gtitle: 'VVoIP 1400'
  tag fix_id: 'F-20178r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
