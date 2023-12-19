control 'SV-18887' do
  title 'VTC systems must be logically or physically segregated on the LAN from data systems, other non-integrated voice communication (VoIP) systems, and by VTC system type.'
  desc 'A common practice in traditional LAN design is the use and implementation of VLANs and IP subnets to segregate services and organizational workgroups, including their traffic as it traverses the LAN. This has the effect of providing confidentiality for the workgroup traffic by limiting the ability of users in other workgroups to see and access the traffic during normal operations. It also enhances the ability to control traffic flows for, and access to, LAN services. Another benefit of using VLANs is that they can improve network performance if they are properly pruned. Typically, when a VLAN is configured on one LAN switch, the other switches in the network will “learn” that VLAN, thus it will propagate throughout the network. This property is not what enhances network performance since it allows broadcast traffic in the VLAN to traverse the entire network. Also, if the number of allowable VLANs that a switch has configured or learns is exceeded, the LAN can become unstable. VLAN pruning eliminates this problem and is actually what can enhance network performance by limiting the traffic that devices in the LAN must process.

The use of a separate IP address space and properly pruned separate VLANs for VTC systems will have the following effects:
 - Enhance the confidentiality of unencrypted VTC traffic.
 - Enhance the confidentiality of the VTC device management traffic, particularly if secure protocols are not available for use.
 - Limit the ability of LAN users to see the VTC devices in other VLANs, which limits the possibility of compromise from user or machine induced malicious activity.

Some VTC systems should be protected using other VLAN structures as follows:
 - Primary conference room systems should have their own closely pruned VLAN and IP subnet. This could be a single conference room or several conference rooms if they are required to communicate with each other or are part of an overall managed VTC network within the enclave. This will provide the maximum protection from compromise for the conference room systems.
 - Hardware-based desktop and office VTUs should be grouped into their own VLAN and IP subnet. This could be the same VLAN and subnet as the one used for conference rooms if these devices are to communicate with them or if they are part of an overall managed VTC network within the enclave.
 - Hardware-based desktop and office VTUs that integrate and signal with the site’s VoIP telephone system may be grouped separately or utilize the Voice system VLAN structure and IP subnet.
 - PC-based soft-VTUs are to be implemented or segregated/controlled as described in the related document covering softphones and soft-VTUs.
 - Local MCUs and VTU management stations must reside in the VTC VLAN and IP subnet with the devices they manage or conference.
 - If WAN access is required, the VLANs can be extended to the enclave boundary.'
  desc 'check', 'Review site documentation to confirm VTC systems are logically or physically segregated on the LAN from data systems, voice (VoIP) systems, and by VTC system type as follows:
 - Verify that there is a dedicated LAN infrastructure and IP address space for the VTC endpoints.
OR
 - Verify that there is a pruned and closed VLAN/IP subnet structure and dedicated IP address space on the LAN for the VTC system(s) that is (are) separate from the VLAN and IP address space/IP subnet structure(s) assigned to data systems and other non-integrated voice communications (VoIP) systems.
 - Verify that VTC systems are segregated on the LAN from themselves and other LAN services as follows: 
- Primary conference room systems
- Hardware-based desktop and office VTUs
Exception 1: If integrated with the VoIP phone system, these devices may connect to the VoIP system VLAN structure.
Exception 2: If part of an overall managed VTC network within the enclave or hardware-based desktop and office VTUs must communicate with the conference room systems within the enclave, these devices may connect to the conference room VLAN structure.
 - Local MCUs and VTU configuration management/control servers must reside in the VTC VLAN and IP subnet with the devices they manage or conference.
 - If WAN access is required, the VLAN(s) or dedicated infrastructure can be extended to the enclave boundary. 

If any of these criteria apply and are not implemented, this is a finding.'
  desc 'fix', 'Implement VTC systems to be logically or physically segregated on the LAN from data systems, voice (VoIP) systems, and by VTC system type. Design dedicated LAN infrastructure and IP address space for the VTC endpoints or implement a pruned and closed VLAN that is separate from the VLAN assigned to data systems and voice (VoIP) systems. 

Implement a separate IP address subnet for the VTC systems separate from the IP address subnet assigned to data systems and other non-integrated voice communications (VoIP) systems. 

Configure ACLs on each routing device in the LAN to limit traffic that needs to cross between the VTC VLANs and the data or management VLAN to authorized traffic based on the service or authorized IP address.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49195r9_chk'
  tag severity: 'medium'
  tag gid: 'V-17713'
  tag rid: 'SV-18887r3_rule'
  tag stig_id: 'RTS-VTC 4120.00'
  tag gtitle: 'RTS-VTC 4120'
  tag fix_id: 'F-48631r6_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
