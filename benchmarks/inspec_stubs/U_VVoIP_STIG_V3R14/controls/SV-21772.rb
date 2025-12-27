control 'SV-21772' do
  title 'A VVoIP core system/device or a  traditional TDM based telecom switch is acting as a network router in that it does not block traffic between its attached management network interfaces(s) (one or more; logical or physical) and/or its production network interface(s) (logical or physical).'
  desc 'Based on a previously stated requirement, a VVoIP system must have one or more production VLANs containing the VVoIP endpoints and a separate OOB management network or virtual management network (management VLAN). Also previously stated is the requirement that the LAN NEs maintain the separation between management network(s) and the production network VLANs by blocking traffic from passing between them. Maintaining this separation is also incumbent upon the managed devices that are connected to both the management and production VLANs.

Individual VVoIP system core devices and traditional TDM based telecom switches connect to their production and management networks or VLANs in different ways. In some cases there are separate dedicated physical management and production interfaces. There may also be one or more physically separate management interfaces. On the other hand these interfaces may be logical or there may be some combination of logical and physical interfaces that support the required production and management traffic. In the event production and management connections use separate interfaces, whether logical or physical, the target/ managed device must not permit one network (physical or logical VLAN) to access another network through the device. That is, the device must not route IP traffic between logical or physical interfaces connected to different VLANs or physical networks that are part of a different logical security zone (protected VLAN) or physical network enclave.

Permitting such routing permit a host on one network or VLAN to gain unauthorized access to a host on another network which can lead to complete corruption of the accessed system or device causing the, loss of availability (denial-of-service), integrity, and information or communications confidentiality.

NOTE: While this specifically addresses a similar situation addressed in the Network Infrastructure STIG that essentially requires that the production side of a managed device must not be accessible from the management interface and vise versa, this requirement extends that requirement to multiple management interfaces. Many DSN switches and DISN IPVS system core devices are managed from the BCPS network and CCSA NOC via one interface and also monitored and potentially managed by the DISA ADIMSS or other NOC. These are separate enclaves which must be protected from inappropriate access between them. In some cases the connections from these enclaves to the managed devices are via separate interfaces on the managed devices. Ergo the requirement the managed device must not pass traffic between these interfaces.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event a VVoIP core device or a traditional TDM circuit switch supports multiple management interfaces that are separate from the production interfaces (as required), ensure the device does not permit traffic to flow between these interfaces.

This is a finding in the event any of the three domains can be reached and therefore potentially compromised from any of the others.

NOTE: While this specifically addresses a similar situation found in the Network Infrastructure STIG, essentially it requires that the production side of a managed device must not be accessible from the management interface and vise versa, this requirement extends that requirement to multiple management interfaces. Many DSN switches and DISN IPVS system core devices are managed from the BCPS network and CCSA NOC via one interface and also monitored and potentially managed by the DISA ADIMSS or other NOC. These are separate enclaves which must be protected from inappropriate access between them. In some cases the connections from these enclaves to the managed devices are via separate interfaces on the managed devices. Ergo the requirement the managed device must not pass traffic between these interfaces.'
  desc 'fix', 'Configure VVoIP core system/devices and traditional TDM based telecom switches to comply with the following: 
In the event a target system/device supports separate IP based production and management interfaces (logical or physical), or multiple management interfaces (logical or physical), connected to different networks or VLANs, ensure the target system/device does not rout IP traffic between the networks or VLANs attached / connected  to these interfaces.
NOTE: this also applies to traditional TDM based telecom switches that are managed via IP networks that connect to the switch via different ports no matter the type of connection (Ethernet or serial).

The purpose of this requirement is to ensure that other devices connected to one side of the target device cannot be accessed or compromised through the target device via one of its other interfaces.

Configure the target system/device to NOT route between multiple attached management networks and/or its production network whether physically different or only logically different by being connected to different VLANs.

NOTE: While this specifically addresses a similar situation addressed in the Network Infrastructure STIG that essentially requires that the production side of a managed device must not be accessible from the management interface and vise versa, this requirement extends that requirement to multiple management interfaces. Many DSN switches and DISN IPVS system core devices are managed from the BCPS network and CCSA NOC via one interface and also monitored and potentially managed by the DISA ADIMSS or other NOC. These are separate enclaves which must be protected from inappropriate access between them. In some cases the connections from these enclaves to the managed devices are via separate interfaces on the managed devices. Ergo the requirement the managed device must not pass traffic between these interfaces.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19631'
  tag rid: 'SV-21772r2_rule'
  tag stig_id: 'VVoIP 5400'
  tag gtitle: 'Deficient Impl’n: Inter interface traffic block'
  tag fix_id: 'F-20335r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
