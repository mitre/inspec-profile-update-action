control 'SV-8823' do
  title 'The implementation of VoIP systems in the local enclave must not degrade the enclaves perimeter protection due to inadequate design of the VoIP boundary and its connection to external networks.'
  desc 'VoIP has the potential to significantly degrade the enclave boundary protection afforded by the required boundary firewall unless the firewall is designed to properly handle VoIP traffic. The typical firewall used to protect an enclave supporting data traffic is not capable of properly handling or supporting real-time communications (VoIP and video conferencing).

Session Initiation Protocol (SIP) and related protocols used for call establishment and control rely on dedicated TCP ports that must be open inbound at all times to receive calls. Real-time Transfer Protocol (RTP) and Real-time Transfer Control Protocol (RTCP) use randomly assigned UDP ports in the range of 1025-65535 with four IP ports required for every bi-directional voice session. The number of ports is increased when video is added. The method of supporting VoIP through a standard data firewall is to open the signaling TCP ports and a broad range of UDP ports for the RTP/RTCP media streams. A data firewall does provide limited protection for VoIP implementations when inbound permit statements are restricted to specific address ranges. This is not possible if calls are to be permitted from any IP address on the Internet or NIPRNet. 

VoIP stateful firewalls and session border controllers, in parallel with the data firewall, provide the best protection for the enclave. Dynamically opening required UDP ports to permit the flow of the media, performing stateful inspection of UDP media packets and dropping all non-session packets, and then closing the UDP ports at the session’s end or after an inactivity timeout greatly increases enclave protection. This configuration provides the capability to decrypt the media streams for inspection and recording. This supports, for CALEA purposes, the monitoring and recording of calls that traverse the enclave boundary.

When a VoIP system is a closed system, such as DISN classified networks, the entire address space of the WAN and connected enclaves is managed by a single system manager. In this instance, a specific limited and segregated address space may be assigned for all VoIP devices in use across the network. The risk to the enclave is limited when a standard firewall is used with inbound permit statements that are based on the segregated IP address range.

Furthermore, when NAT is used, the VoIP stateful firewall or session border controller provide RFC 1918 internal private addressing, allowing RTP/RTCP packets to traverse the boundary. Although NAT is no longer required to be implemented, it is still a common security best practice.'
  desc 'check', 'If the local enclave VoIP implementation is a stand-alone system and does not connect to external networks, this requirement is Not Applicable. The enclave must be a closed DISN classified network or an organizational intranet, the PMO must designate and implement a segregated IP address range for use by VVoIP systems, and no dedicated VoIP firewall function (as defined in the current UCR) is implemented to meet this exception. In all other cases, this requirement is Applicable.

Review the VoIP System Security Plan (SSP), VoIP Access Control Plan (ACP), and other VoIP design documentation. Visually inspect the enclave boundary protection hardware and its connections to ensure it is implemented as documented in the design.

Review the VoIP System Security Plan (SSP), VoIP Access Control Plan (ACP), and other VoIP configuration documentation. Ensure the enclave boundary protection is designed and implemented to protect the VoIP infrastructure and the data enclave. Interview the ISSO to confirm compliance.

The data firewall function must protect the VoIP sub-enclave and infrastructure by:
1. Blocking all VoIP traffic to/from the VoIP production VLANs, except for signaling and media traffic to/from a remote endpoint entering the enclave via a properly authenticated and encrypted tunnel, where VoIP traffic is blocked from data VLANs.
2. Blocking all non-VoIP traffic to/from the VoIP production VLANs. 
3. Blocking all non-VoIP traffic to/from the VoIP management VLANs, except for VoIP system management traffic to/from specifically authorized management servers and workstations (local or in a remote NOC).
4. Allow all VoIP traffic to/from the VoIP production VLANs, including SIP and SRTP traffic encrypted and encapsulated on port 443.
5. Inspecting all non-VoIP traffic to/from the VoIP management VLANs specifically required for VoIP system management. This may be performed by a separate IDPS function or an alternate data perimeter may be implemented for this purpose.

The VoIP firewall function must protect the VoIP sub-enclave and infrastructure by:
1. Blocking all non-VoIP traffic to/from data production VLANs, data management VLANs, and VoIP management VLANs. 
2. Inspecting all VoIP traffic to/from the VVoIP production VLANs.
3. Supporting interoperability and assured service requirements per the DoD UCR.

When PSTN commercial service connects to the enclave, the connection must be through a VoIP media gateway function to protect the VoIP sub-enclave and infrastructure. This includes PRI, CAS, and POTS analog lines.

If the enclave boundary protection network elements and connections are not implemented as documented, this is a finding. 

If the data firewall function, VoIP firewall function, and VoIP media gateway function do not protect the VoIP sub-enclave and infrastructure, this is a finding.'
  desc 'fix', 'For all VoIP systems implemented in the local enclave with connections to external networks, ensure the design maintains enclave boundary protection for data and voice video sub-enclaves, maintaining separation within the LAN and support for interoperability of various vendor system implementations in different enclaves. 

Design and implement the enclave boundary protection to provide an IDPS function, data firewall function, VoIP firewall function, and VoIP media gateway function.

The IDPS function must protect the VoIP sub-enclave and infrastructure by:
- Inspecting all non-VoIP traffic to/from the VoIP management VLANs specifically required for VoIP system management.

The data firewall function must protect the VoIP sub-enclave and infrastructure by:
1. Blocking all VoIP traffic to/from the VoIP production VLANs, except for signaling and media traffic to/from a remote endpoint entering the enclave via a properly authenticated and encrypted tunnel, where VoIP traffic is blocked from data VLANs.
2. Blocking all non-VoIP traffic to/from the VoIP production VLANs. 
3. Blocking all non-VoIP traffic to/from the VoIP management VLANs, except for VoIP system management traffic to/from specifically authorized management servers and workstations (local or in a remote NOC).
4. Allow all VoIP traffic to/from the VoIP production VLANs, including SIP and SRTP traffic encrypted and encapsulated on port 443.

The VoIP firewall function must protect the VoIP sub-enclave and infrastructure by:
1. Blocking all non-VoIP traffic to/from data production VLANs, data management VLANs, and VoIP management VLANs. 
2. Inspecting all VoIP traffic to/from the VVoIP production VLANs.
3. Supporting interoperability and assured service requirements per the DoD UCR.

The VoIP media gateway function must protect the VoIP sub-enclave and infrastructure by:
- Connecting all PSTN commercial services to the enclave through a VoIP media gateway, including PRI, CAS, and POTS analog lines.

Document the design and implementation in the VoIP System Security Plan (SSP), VoIP Access Control Plan (ACP), and other VoIP design and configuration documentation. Confirm through visual inspection the enclave boundary protection hardware and its connections are implemented as documented. Ensure the enclave boundary protection is designed and implemented to protect the VoIP infrastructure and the data enclave.

NOTE: in the event the enclave is part of an organizational intranet, and there is no firewall at the local enclave perimeter, configure the perimeter/premise router to provide the required filtering and routing along with ensuring all inbound and outbound traffic enters the required dedicated circuit or encrypted VPN. Specific network requirements for organizational intranet design and implementation is beyond the scope of this document.'
  impact 0.7
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23854r4_chk'
  tag severity: 'high'
  tag gid: 'V-8328'
  tag rid: 'SV-8823r4_rule'
  tag stig_id: 'VVoIP 1005'
  tag gtitle: 'VVoIP 1005'
  tag fix_id: 'F-20286r4_fix'
  tag 'documentable'
end
