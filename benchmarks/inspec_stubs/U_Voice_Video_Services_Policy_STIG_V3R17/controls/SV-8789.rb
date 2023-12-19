control 'SV-8789' do
  title 'VVoIP system components must receive IP address assignment and configuration information from a DHCP server with a dedicated scope to the VVoIP system.'
  desc 'When using Dynamic Host Configuration Protocol (DHCP) for address assignment and host configuration, different DHCP scopes (different address space, subnets, and VLANs) must be used for voice components and data components. Optimally, the design would place a DHCP server dedicated to providing IP address and configuration information to the VVoIP system components separate from the IP address and configuration information to data system components. The DHCP server providing VVoIP devices should be in a Voice Video and/or Unified Capability (UC) domain having the same address space and VLAN to prevent DHCP requests routed onto the data environment that degrade the separation of the VVoIP environment and the data environment. With centralized management of DHCP (and other services, such as DNS) this separation is obviously eliminated. DHCP requests and responses for voice must reside on a separated VLAN.'
  desc 'check', 'Verify the VVoIP system design uses DHCP for VVoIP system component IP address assignment and configuration, to include core components and endpoints. Ensure the design incorporates a different DHCP server than used for data system components and hosts. Confirm these servers reside in their respective voice or data address space and VLAN.

Voice Video soft clients and associate Unified Capabilities (UC) applications residing on workstations will, by default, utilize the workstation IP information from the data DHCP server, unless the workstation and soft client is capable of multiple VLANs, and the soft client is assigned to the VVoIP VLAN. The soft client residing in the Voice Video VLAN is preferred.

If the VVoIP system design does not use DHCP for VVoIP system component IP address assignment and configuration, this is a finding.

If the VVoIP system design does not use DHCP for VVoIP endpoint IP address assignment and configuration, this is a finding. 

If the DHCP servers or scopes are not dedicated to the VVoIP system (separate from the data system and host DHCP server), this is a finding.

If the DHCP server is not deployed in the core VVoIP VLAN with an appropriate IP address within the dedicated VVoIP address space, this is a finding.'
  desc 'fix', 'Implement in the VVoIP system design, DHCP servers for VVoIP system component and endpoint IP address assignment and configuration. The design must use a different DHCP server for VVoIP than for data components and hosts. These servers must reside in the VVoIP address space and VLAN.

Voice Video soft clients and associate Unified Capabilities (UC) applications residing on workstations will, by default, utilize the workstation IP information from the data DHCP server, unless the workstation and soft client is capable of multiple VLANs, and the soft client is assigned to the VVoIP VLAN. The soft client residing in the Voice Video VLAN is preferred.

Design preference for the VVoIP DHCP server shall be given to the following order of preference: 
- A dedicated device
- A function of the VVoIP session manager (LSC/MFSS)
- A function of other VVoIP related server
- An infrastructure router inside the VVoIP network space

NOTE: The Network Infrastructure STIG precludes the implementation of a DHCP server on a perimeter router.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23793r2_chk'
  tag severity: 'low'
  tag gid: 'V-8294'
  tag rid: 'SV-8789r2_rule'
  tag stig_id: 'VVoIP 5210'
  tag gtitle: 'VVoIP 5210'
  tag fix_id: 'F-20239r2_fix'
  tag 'documentable'
end
