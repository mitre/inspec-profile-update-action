control 'SV-4636' do
  title 'A Secure WLAN (SWLAN) must conform to an approved network architecture.'
  desc 'Approved network architectures have been assessed for IA risk.  Non-approved architectures provide less assurance than approved architectures because they have not undergone the same level of evaluation.'
  desc 'check', 'Detailed Policy Requirements:

The SWLAN architecture conforms to one of the approved configurations: 
LAN Extension: This architecture provides wireless access to the wired infrastructure using a Harris SecNet 11/ 54 or L3 KOV-26 Talon. In this architecture, the boundary is controlled either with fencing or inspection. See Figure 2.2 in the DISA FSO Wireless Overview for an example of the LAN Extension architecture.

Wireless Bridging: This architecture provides point-to-point bridging using Harris SecNet 11/ 54 or Talon. In this architecture, the boundary is controlled either with fencing or inspection. See Figure 2.3 in the DISA FSO Wireless Overview for an example of the Wireless Bridging architecture.

Wireless Peer-to-Peer: This architecture provides point-to-point communications between wireless clients using Harris SecNet 11/ 54 or Talon. In this architecture, the boundary is controlled either with fencing or inspection. See Figure 3.2 in the DISA FSO Wireless Overview for an example of the Wireless Peer-to-Peer architecture.

Check Procedures:

Interview the SA or IAO to obtain SWLAN network diagrams.  Review the SWLAN architecture and ensure it conforms to one of the approved use cases.'
  desc 'fix', 'Disable or remove the non-compliant SWLAN or reconfigure it to conform to one of the approved architectures.'
  impact 0.7
  ref 'DPMS Target L3 KOV-26 Talon'
  tag check_id: 'C-16036r1_chk'
  tag severity: 'high'
  tag gid: 'V-4636'
  tag rid: 'SV-4636r1_rule'
  tag stig_id: 'WIR0210'
  tag gtitle: 'SWLAN architecture'
  tag fix_id: 'F-34117r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1, ECWN-1'
end
