control 'SV-21771' do
  title 'VVoIP endpoints must receive IP address assignment and configuration information from a DHCP server with a dedicated scope to the VVoIP system.'
  desc 'When using Dynamic Host Configuration Protocol (DHCP) for address assignment and host configuration, different DHCP scopes (different address space, subnets, and VLANs) must be used for voice components and data components. Optimally, the design would place a DHCP server dedicated to providing IP address and configuration information to the VVoIP endpoints separate from the IP address and configuration information to data hosts (workstations etc.). The DHCP server providing VVoIP devices should be in a Voice Video and/or Unified Capability (UC) domain having the same address space and VLAN to prevent DHCP requests routed onto the data environment that degrade the separation of the VVoIP environment and the data environment. With centralized management of DHCP (and other services, such as DNS) this separation is obviously eliminated. DHCP requests and responses for voice must reside on a segregated VLAN.

The best practice is to manually assign addresses when authorizing the instrument by generating its configuration file. In the event a dedicated DHCP server for VVoIP endpoints is not implemented, the network (i.e., the router controlling access to and from the VVoIP endpoint VLANs) must route VVoIP endpoint DHCP requests directly to the DHCP server in such a manner that prevents traffic to flow between the VVoIP and data VLANs. Additionally the DHCP server must prevent such traffic flows while providing the VVoIP endpoints with proper VVoIP addresses and other information within the VVoIP address/subnet range (scope).'
  desc 'check', 'For VVoIP system designed to use DHCP for VVoIP endpoint address assignment/configuration, ensure the following:
- The DHCP server provides addresses from the segregated VVoIP address space and associated configuration information to VVoIP endpoints exclusively.
- In the event the DHCP server is not unique to VVoIP, ensure it does not provide data addresses and configuration information to the VVoIP endpoints, and conversely does not provide VVoIP addresses and configuration information to the data endpoints (hosts or workstations).
- In the event the DHCP server is not unique to VVoIP, ensure the DHCP server and associated network routing prevents traffic to flow between the VVoIP VLANs and data VLANs.

Review VVoIP network design to determine the IP address the of VVoIP DHCP server. Alternately, determine the VLAN tag the VVoIP DHCP server uses or responds to or inspect the Ethernet port configuration of the LAN network equipment connected to the DHCP server to determine the VLAN assigned to the port.

If the DHCP server or relay agent IP address is not within the designated VVoIP VLAN structure or IP address range, this is a finding.

Inspect the configuration of all DHCP servers within the enclave to determine their address scope(s), and placement within the network for the VVoIP, data, or other VLANs.

If the DHCP scope providing address and network configuration information to data components or hosts, and provides this information to VVoIP endpoints or other system components, this is a finding.

Conversely, if a DHCP scope providing address and network configuration information to VVoIP endpoints, also provides VVoIP addresses and information to data components, hosts, or other non-VVoIP system components, this is a finding.

Note: Dedicated hardware video conferencing endpoints integrated into the VVoIP system, (i.e., establishes calls/sessions by signaling with the VVoIP LSC) may utilize the services of the VVoIP DHCP server. Dedicated hardware video conferencing endpoints not associated with an LSC are required to reside in their own system of VLANs and therefore should have their own DHCP server or be statically addressed.'
  desc 'fix', 'Configure the DHCP server supporting VVoIP endpoints to have different DHCP scopes used for VVoIP components, data components, and independent video conferencing endpoints.

Ensure these servers reside in their respective voice, video, or data address space. VLANs and the VVoIP endpoints (or independent video conferencing endpoints) only receive address and configuration information from the DHCP scope dedicated to them.

Alternately, when a unique DHCP server is not implemented for VVoIP address space, ensure the VVoIP DHCP scope provides addresses and associated configuration information to VVoIP endpoints for the segregated VVoIP address space.

Ensure the VVoIP DHCP scope does not provide data addresses and configuration information to the VVoIP endpoints.

Conversely, ensure the data DHCP scope does not provide VVoIP address and configuration information to the data endpoints (hosts or workstations).

Further ensure the DHCP server and associated network routing prevents traffic to flow between the VVoIP VLANs and data VLANs.

Note: Dedicated hardware video conferencing endpoints integrated into the VVoIP system, (i.e., establishes calls/sessions by signaling with the VVoIP LSC) may utilize the services of the VVoIP DHCP server. Dedicated hardware video conferencing endpoints not associated with an LSC are required to reside in their own system of VLANs and therefore should have their own DHCP server or be statically addressed.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23954r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19630'
  tag rid: 'SV-21771r4_rule'
  tag stig_id: 'VVoIP 5235'
  tag gtitle: 'VVoIP 5235'
  tag fix_id: 'F-20334r4_fix'
  tag 'documentable'
end
