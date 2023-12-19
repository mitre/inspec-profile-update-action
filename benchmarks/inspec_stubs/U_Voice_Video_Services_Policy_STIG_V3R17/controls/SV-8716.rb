control 'SV-8716' do
  title 'The VVoIP VLAN design for the supporting LAN must provide segmentation of the VVoIP service from the other services on the LAN and between the VVoIP components such that access and traffic flow can be properly controlled.'
  desc 'An IPT system is built on an IP infrastructure based on layer 2 and layer 3 switches and routers, which comprise the network’s access and distribution layers respectively. The layer 2 switches found at the access layer provide high port density for both host and IP phone connectivity as well as layer 2 services such as QoS and VLAN membership. (It should also be mentioned that some access layer switches can also do layer 2 and 3 filtering.) Guidelines and requirements for securing access layer devices including any associated cross-connect hardware can be found in the Network Infrastructure STIG. Layer 2 network segregation is the second layer in our layered defense approach to VoIP security. Voice traffic must be isolated from data traffic using separate physical LANs or Virtual LANs. The combination of data and voice segregation and segmentation using VLANs along with a switched infrastructure strongly enhances the security posture of the system. This will also help to mitigate call eavesdropping and other attacks. VLAN technology has traditionally been an efficient way of grouping users into workgroups to share a specific network address space and broadcast domain regardless of their physical location on the network. Hosts within the same VLAN can communicate with other hosts in the same VLAN using layer-2 switching. To communicate with other VLANs, traffic must go through a layer 3 device where it can be filtered and routed. VLANs can offer significant benefits in a multi-service network by providing a convenient way of isolating VVoIP equipment and traffic from the data equipment and traffic. When VLANs are deployed, excessive broadcast and multicast packets present in the normal data traffic will not disrupt IPT services. As with data networks, IPT equipment and instruments should be logically grouped using multiple VLANs such that IP Phones share their VLANs only with other IP Phones, gateways with like gateways, and so on. Each type of VVoIP device would have mutually exclusive VLANs. This forces layer 3 routing and thereby enables all the filtering capabilities of the layer 3 devices. Additionally, each server type should have its own VLAN. Private server VLANs would prevent a compromised server from attacking another server on the same VLAN at layer two. Since all the devices on any given VLAN would have the same Layer 2 through 4 (at least) characteristics the filtering rules become easier to develop, deploy, and manage. Additionally, the implementation of VLANs helps to mitigate the risk of attacks sourced from the data VLANs such as virus driven DoS attack or packet sniffing. In addition, placing voice and data traffic into separate VLANs will reduce competition for the network and thus reduce latency (queue/wait time) for transmission services, which will reduce the possibility of denial of voice services. This also reduces the Ethernet broadcast domain thereby reducing network overhead. Since VoIP is very latency sensitive this segmentation approach is the most economical way to improve performance in an existing network infrastructure.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Ensure the VVoIP system and the supporting LAN are designed and implemented using multiple VLANs to segregate the VVoIP core equipment and endpoints and services from all other hosts and services (such as data and dedicated VTC) running on the LAN such that the security, QoS, and reliability of the VVoIP system/service is enhanced thus allowing VVoIP system traffic and access control using router ACLs.

VLANs and subnets will be provided and equipment separated, for those devices that are implemented in the system, as follows:
> Hardware Endpoints: multiple VLANs generally in parallel with data LAN VLANs the number of which is dependent on the size of the LAN and as required for the reduction of broadcast domains per good LAN design. For small networks there will be a minimum of one.
> Software endpoints on workstations: multiples as with hardware endpoints. Voice and data traffic may coexist on the data VLAN when leaving the workstation. Based on the Unified Capabilities Requirements (UCR) requirement that the Unified Capabilities (UC) application tag its signaling and media traffic with the proper UCR defined Differentiated Service Code Point (DSCP), the LAN access switch port must route the UC traffic to the voice/video VLAN. If the LAN access switch is not capable, then routing upstream must perform this. A separate NIC is not required for UC VLANs.
> VVoIP system core control equipment containing the LSC, endpoint configuration server, and DHCP server if used, etc.
> Media gateways (MG) to the DSN and PSTN.
> Signaling gateways (SG) to the DSN. 
> DoD WAN access VVoIP firewall (SBC or other).
> Voicemail / Unified Messaging Servers. These may need to be accessible from both the voice and data VLANs.
> UC servers such as those supporting unified messaging, IM/presence, “web” browser based conferencing, and directory services. These may need to be accessible from both the voice and data VLANs.

NOTE: Hardware based VTC endpoints that utilize LSC services for session control may reside in the VoIP endpoint VLANs. These may include desktop and “executive” or office based units. All other Hardware based VTC endpoints require their own dedicated network or VLAN. 

NOTE: Separate VLANs work in conjunction with the dedicated address space discussed earlier to provide the required effect. Each VLAN is configured with a subset of addresses (valid IP subnet) from the designated VVoIP address space
NOTE: Per NI STIG requirements the NE’s default VLAN (VLAN 0 or 1) will not be used for any of the required VVoIP, data, or VTC VLANs.

NOTE: ACLs are required between the various VLANs that will filter traffic between them based on what protocols and IP addresses are permitted to access or control the devices residing in the VLAN. Therefore it is expected that the LAN / VVoIP system design will include one or more routers or layer-3 switches as the intersection of all of these VLANs to access and traffic flow between them. This routing device will be configured with ACLs to only permit the functionally necessary traffic to flow between the various VLANs and the equipment they contain. 

NOTE: These VLANs may be replaced by direct connections to the VVoIP core routing devices so that the ACLs may be implemented on the physical interface to the device. This requires that such direct physical connections be given a discrete subnet. 

NOTE: The VLAN/subnets and associated ACLs need only to be assigned / applied for devices that exist in the VVoIP system. The VLAN / ACL design may change depending upon the location and physical makeup of the VVoIP core equipment. An example of this is if a MG and SG reside on the same platform and both use the same Ethernet LAN connections (and potentially the same or different IP address), then separate VLANs are not needed for the MG and SG but the ACL protecting them may need to be adjusted accordingly. 

This is a finding in the event the design or implementation of the VVoIP system and supporting LAN does not include the required VLANs and subnets based upon the equipment and services provided by or included in the VVoIP system. Size of the system or the number of users supported has no effect on the need for this segmentation. However under some circumstances such as in the case of a small deployable package the number of VLANs can be reduced based upon a benefit vs. risk assessment, AO approval, and package C&A.

NOTE: The existence of the required VLANs will be validated in subsequent computing checks. The purpose of this check is to determine if the system design and implementation plan includes consideration for VLAN segmentation.'
  desc 'fix', 'Deploy VVoIP systems and components on a dedicated VLAN structure that is separate from the data network VLAN structure. A minimum of one VLAN is required. More than one is highly recommended. Ensure the VVoIP system and the supporting LAN are designed and implemented using multiple VLAN/subnets to segregate the VVoIP core equipment and endpoints and services from all other hosts and services (such as data and dedicated VTC) running on the LAN such that the security, QoS, and reliability of the VVoIP system/service is enhanced thus allowing VVoIP system traffic and access control using router ACLs. 
VLAN and subnets will be provided and equipment separated as follows:
> Hardware Endpoints: multiple VLAN/subnets generally in parallel with data LAN VLANs the number of which is dependent on the size of the LAN and as required for the reduction of broadcast domains per good LAN design. For small networks there will be a minimum of one.
> Software endpoints on workstations: multiples as with hardware endpoints. Voice and data traffic may coexist on the data VLAN when leaving the workstation. Based on the Unified Capabilities Requirements (UCR) requirement that the Unified Capabilities (UC) application tag its signaling and media traffic with the proper UCR defined Differentiated Service Code Point (DSCP), the LAN access switch port must route the UC traffic to the voice/video VLAN. If the LAN access switch is not capable, then routing upstream must perform this. A separate NIC is not required for UC VLANs.
> VVoIP system core control equipment containing the LSC, endpoint configuration server, and DHCP server if used, etc.
> Media gateways to the DSN and PSTN
> Signaling gateways (SG) to the DSN 
> DoD WAN access VVoIP firewall (SBC or other)
> Voicemail / Unified Messaging Servers. These may need to be accessible from both the voice and data VLANs.
> UC servers such as those supporting IM/presence, web browser based conferencing, and directory services. These may need to be accessible from both the voice and data VLANs.

NOTE: These VLAN/subnets may be replaced by direct connections to the VVoIP core routing devices so that the ACLs may be implemented on the physical interface to the device. This requires that such direct physical connections be given a discrete subnet. 

NOTE: The VLAN/subnets and associated ACLs need only to be assigned / applied for devices that exist in the VVoIP system. The VLAN / ACL design may change depending upon the location and physical makeup of the VVoIP core equipment. An example of this is if a MG and SG reside on the same platform and both use the same Ethernet LAN connections (and potentially the same or different IP address), then separate VLANs are not needed for the MG and SG but the ACL protecting them may need to be adjusted accordingly.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23801r3_chk'
  tag severity: 'medium'
  tag gid: 'V-8230'
  tag rid: 'SV-8716r2_rule'
  tag stig_id: 'VVoIP 5500 (LAN)'
  tag gtitle: 'VLAN segregation for VVoIP'
  tag fix_id: 'F-20253r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This finding can be reduced to a cat III in the event the system minimally implements one VLAN for endpoints and one for the core equipment.

This may not be a finding under certain circumstances such as in the case of a small footprint tactical system where there are a limited number of VVoIP instruments (i.e., 20). This package system must have been accredited via the appropriate test exercises and configured in accordance with the accreditation. This override is partially driven by the difficulty in supporting a complex configuration for these small systems in deployed environments. This Severity Override does not apply to strategic systems (i.e., systems implemented on a base or fixed DOD facility) or large relatively fixed tactical deployments.'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCBP-1, DCPA-1, ECSC-1'
end
