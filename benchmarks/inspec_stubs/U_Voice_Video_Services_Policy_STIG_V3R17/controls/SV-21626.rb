control 'SV-21626' do
  title 'The VVoIP system and LAN design must provide segmentation and protection of the VVoIP system core device management traffic and interfaces such that role based access and traffic flow can be properly controlled.'
  desc 'The management interface on any system/device is its Achilles heel. Unauthorized access can lead to complete corruption of the system or device, causing the loss of availability (denial-of-service), integrity, and information or communications confidentiality. As such management interfaces and the management traffic they transmit or receive must be protected. The most effective method for providing this protection is to establish a separate dedicated network for the purpose of managing systems, devices, and network elements. Such a network is typically called an out-of-band (OOB) management network. Such networks can be expensive to establish depending on the geographical placement of the managed devices. This protection can also be afforded the management interfaces and traffic on the same network as the production traffic uses, but the process is more difficult and protection requirements more stringent. This method is called In-Band management. When using in-band management, the most effective method for providing management interface and traffic protection is to establish a separate dedicated management VLAN on the production network. Another method for protecting management traffic is the use of secure protocols and encryption. The Network Infrastructure STIG defines the requirements for both in-band and OOB management. In-band management is permitted for the typically geographically disbursed network elements using a dedicated management VLAN and logically separate management interfaces on each NE. In general the management of VVoIP core systems and devices must follow the NI STIG/checklist guidance. This means that these systems/devices can be managed via an OOB management network or an in –band VLAN. While this is the case, the this management access must be segregated from all other management VLANs on the network. The purpose of the separate VVoIP management VLAN or OOB network is to provide for separation of access in support of separation of duties between the data network or server SAs and the VVoIP system SAs. In some organizations these SAs are from different departments or just have different duties that don’t require that they have access to all devices on the network. The VVoIP management VLAN or OOB network may be accessed from the general LAN management VLAN/OOB network or other management VLANs or networks via a controlled ACL, gateway. A firewall may be needed if crossing enclave boundaries.'
  desc 'check', 'Inspect the connections to and the configurations of the VVoIP system core devices and those of the core LAN elements that support them. Look for the dedicated management LAN or VLAN to confirm that one has been implemented.

Verify the voice/video system (VVoIP system and/or TDM switch) management is segregated or separated from production traffic and other management traffic and such that access and traffic flow can be properly controlled and role based access is supported. 

If the VVoIP system and LAN is not designed to provide the necessary separation of the management traffic and interfaces or such separation is not implemented as described above or at all, this is a finding.

NOTE: This may be implemented using a separate voice system management VLAN or OOB network, the purpose of which is to provide for separation of access paths in support of separation of duties between the data network and server SAs and the VVoIP or TDM system SAs. This VLAN may be accessed from the general LAN management VLAN via a controlled ACL, gateway or firewall if needed.'
  desc 'fix', 'Implement a dedicated OOB network or closed virtual In-band network (VLAN) for the VVoIP system and connect the core device management interfaces to it in compliance with the following requirement: 

Ensure VVoIP system management is segregated or separated from production traffic and other management traffic and such that access and traffic flow can be properly controlled and role based access is supported.

NOTE: the purpose of the separate VVoIP management VLAN or OOB network is to provide for separation of access in support of separation of duties between the data network or server SAs and the VVoIP system SAs. This VLAN may be accessed from the general LAN management VLAN via a controlled ACL, gateway or firewall if needed.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23803r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19562'
  tag rid: 'SV-21626r2_rule'
  tag stig_id: 'VVoIP 5505 (LAN)'
  tag gtitle: 'Segregated VVoIP management'
  tag fix_id: 'F-20254r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCBP-1, DCPA-1, DCSP-1, ECSC-1'
end
