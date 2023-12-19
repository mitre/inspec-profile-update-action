control 'SV-17084' do
  title 'Deploying Unified Communications (UC) soft clients on DoD networks must have Authorizing Official (AO) approval.'
  desc 'This use case addresses situations whereby UC soft client applications on workstations are not the primary voice communications device in the work area. This means that there is a validated mission need and the number of UC soft clients permitted to operate inside the LAN will be less than the number of hardware based phones in the LAN. This number should be limited to those UC soft clients required to meet specific mission requirements. There are scenarios for the use of limited numbers of UC soft clients in the strategic LAN. The first of these scenarios is providing support for UC soft clients associated with a VoIP system in another enclave. This is a remote access scenario and must operate as they would in a normal remote access use case. If this scenario is approved, special accommodations must be made in the local LAN to support users from a remote LAN and permit them to connect to their home enclave. This could include segregating them on a separate dedicated LAN with its own boundary protection or by implementing a dedicated VLAN protection zone while opening the enclave boundary to permit the remote connection. 

Voice/video and data must reside on separate VLANs for the protection of the voice infrastructure. However, recognizing that requiring a NIC to be configured to support voice/video and data VLANs is not a viable solution, voice and data traffic can coexist in the data VLAN when leaving the workstation. Based on the Unified Capabilities Requirements (UCR) requirement that the Unified Capabilities (UC) application tag its signaling and media traffic with the proper UCR defined Differentiated Service Code Point (DSCP), the LAN access switch port can route the UC traffic to the voice/video VLAN. If the LAN access switch is not capable, then routing upstream must perform this. A separate NIC is not required to support VLANs for voice and video segmentation under UC.'
  desc 'check', 'Ensure the responsible AO approves the use of limited numbers of UC soft clients in the strategic LAN along with the measures implemented to protect these UC soft clients and the local VoIP and data infrastructure. Approval will be provided in writing and will be maintained by the ISSO for inspection by IA reviewers or auditors.

When limited numbers of UC soft clients associated with the local VoIP system are implemented in the strategic LAN, a separate VLAN structure must be implemented for them. Implementation of a VLAN must not provide a bridge between the VoIP and data VLANs. Traffic must be filtered such that the UC soft client’s VoIP traffic is routed to the VoIP VLAN while all other traffic is routed to the data VLAN. A separate NIC is not required to support VLANs for voice and video segmentation under UC.

NOTE: Limited numbers in this scenario means as few as possible, but may mean 25 or 30 percent of the overall PCs on the LAN. Beyond this percentage, the protections afforded by this implementation become limited or negated because of the large number of PCs in the UC soft client VLAN.

Determine if limited numbers of UC soft clients are permitted to operate or are implemented in the strategic LAN. If so, review the written AO approval for the implementation. If limited numbers of UC soft clients are to be implemented in the strategic LAN without written AO approval for the implementation, this is a finding.'
  desc 'fix', 'Ensure the responsible AO approves the use of UC soft clients in the strategic LAN along with the measures implemented to protect UC soft clients and the local VoIP and data infrastructure. Approval must be provided in writing and will be maintained by the ISSO for inspection by IA reviewers or auditors. UC soft clients do not provide assured services and therefore cannot be used as the primary method of communications for those personnel requiring assured services.

When limited numbers of UC soft clients are to be implemented in the strategic LAN, obtain written approval from the responsible AO along with approval for the measures implemented to protect these UC soft clients and the local VoIP and data infrastructure. Alternately remove the UC soft clients from the LAN.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17140r3_chk'
  tag severity: 'medium'
  tag gid: 'V-16096'
  tag rid: 'SV-17084r3_rule'
  tag stig_id: 'VVoIP 1720'
  tag gtitle: 'VVoIP 1720'
  tag fix_id: 'F-16201r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority', 'Information Assurance Manager']
end
