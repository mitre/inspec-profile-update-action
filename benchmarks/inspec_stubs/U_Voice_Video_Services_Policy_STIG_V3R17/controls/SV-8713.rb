control 'SV-8713' do
  title 'VVoIP system components must use separate address blocks from those used by non-VVoIP system devices.'
  desc 'VVoIP networks increasingly represent high-value targets for attacks and represent a greater risk to network security than most other network applications; hence, it is imperative that the voice network and supporting data networks be secured as tightly as possible to reduce the impact that an attack can have on either network. Segregating voice traffic from data traffic greatly enhances the security and availability of all services. Further subdivision of the voice and data networks can further enhance security. Achieving the ideal security posture for voice and data would require two physically separate and distinct networks (including cable plant), much as is the case with traditional voice and data technologies. Although this might be considered for the most demanding security environments, it works against the idea of convergence and the associated cost savings expected by having one network (and cable plant). Logical separation of VVoIP components and data components can be accomplished at both Layer 2 using Virtual Local Area Networks (VLANs) and Layer 3 using IP addressing. While these methods are not security mechanisms, they do provide a derived security benefit by easing management of filtering rules and obfuscating or hiding addresses and information that an attacker could use to facilitate an attack. Separation may also prevent an attack on one network from affecting the other. These methods make it harder for an attacker to be successful and help to provide a layered approach to VVoIP and network security. Segregating data from telephony by placing VVoIP servers and subscriber terminals on logically separate IP networks and logically separate Ethernet networks while controlling access to these VVoIP components through filters will help to ensure security and aid in protecting the VVoIP environment from external threats. In addition, further subdivision of those components is necessary to protect the telephony applications running across the infrastructure. Layer 3 address separation is the first layer in our layered defense approach to VVoIP security. It allows the use of switches, routers, and firewalls with their associated access control lists (ACL) and other processes, to control traffic between the components on the network. To provide address separation, best practices dictate that all like components be placed in like address ranges. Therefore VVoIP components (i.e., Gatekeepers, Call Managers, voice mail systems, IP Subscriber Terminals etc.) will be deployed within their own, separate private IP network, logical sub-network, or networks. The combination of logical data and voice segmentation via addressing and VLANs coupled with a switched and routed infrastructure strongly mitigates call eavesdropping and other attacks. In addition, limiting logical access to VVoIP components is necessary for protecting telephony applications running across the infrastructure. Separating data from telephony by placing VVoIP servers and subscriber terminals on logically separate IP networks while controlling access to these VVoIP components through IP filters will help to ensure security and aid in protecting the VVoIP environment.'
  desc 'check', 'Verify a dedicated address block is defined for the VVoIP system separate from the address blocks used by non-VVoIP system devices, ensuring traffic and access control using firewalls and router ACLs. 

If the LAN under review is a closed unclassified LAN, an unclassified LAN connected to an unclassified WAN (such as the NIPRNet or Internet), a closed classified LAN, or a classified LAN connected to a classified WAN (such as the SIPRNet), this requirement is applicable. In the case of a classified WAN where network wide address based accountability or traceability is required by the network PMO, the PMO must provide segregated, network wide address blocks so that the attached classified LANs meet this requirement.

Affected devices include core and adjunct components, including session managers, session border controller (SBC), media and signaling gateway interfaces, customer edge (premise) router internal interface to the Voice Video VLANs, associated UC components, and VVoIP hardware endpoints. 

If a dedicated LAN address block is not designated for the VVoIP system, separated from the address space used for the general LAN and management VLANs, this is a finding.'
  desc 'fix', 'Implement VVoIP systems and components on a logically segregated and dedicated VVoIP network. Ensure dedicated address blocks or ranges are defined for the VVoIP system, separate from the address blocks used for non-VVoIP system devices thus allowing traffic and access control using firewalls and router ACLs. 

This requirement applies to the following: 
- A closed unclassified LAN.
- An unclassified LAN connected to an unclassified WAN (such as the NIPRNet or Internet).
- A closed classified LAN. 
- A classified LAN connected to a classified WAN (such as the SIPRNet).'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23790r3_chk'
  tag severity: 'medium'
  tag gid: 'V-8227'
  tag rid: 'SV-8713r3_rule'
  tag stig_id: 'VVoIP 5200'
  tag gtitle: 'VVoIP 5200'
  tag fix_id: 'F-20236r3_fix'
  tag 'documentable'
end
