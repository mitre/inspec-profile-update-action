control 'SV-21769' do
  title 'VVoIP component(s) are NOT addressed using the defined dedicated VVoIP system addresses'
  desc 'The protection of the VVoIP  system is enhanced by ensuring all VVoIP systems and components within the LAN (Enclave) are deployed using separate address blocks from the normal data address blocks. This is one of the required steps required to help protect the VVoIP infrastructure and services by allowing traffic and access control via firewalls and router ACLs.'
  desc 'check', 'Ensure all VVoIP systems and components within the LAN (Enclave) are deployed using the dedicated VVoIP address space defined in the VVoIP system design for the given network type.

Inspect the VVoIP core equipment components (endpoints checked separately) to determine if they are addressed using the dedicated VVoIP address space defined in the VVoIP system design for the given network type. 

NOTE: The affected devices in this case are as follows:
> VVoIP Call or session controllers; LSC / MFSS 
> Adjunct UC systems
> Edge Boundary Controller (EBC) internal and external interfaces
> Customer Edge (Premise) router internal interface to the VVoIP VLANs'
  desc 'fix', 'Ensure all VVoIP systems and components within the LAN (Enclave) are deployed using the using the dedicated VVoIP address space defined in the VVoIP system design for the given network type.

NOTE: This is applicable to the following:
> A closed unclassified LAN
> A unclassified LAN connected to a unclassified WAN such as the NIPRNet or Internet
> A closed classified LAN 
> A classified LAN connected to a classified WAN (such as the SIPRNet).

NOTE: In the case of a classified WAN where network wide address based accountability or traceability is required by the network PMO, the PMO must provide a segregated, network wide address block(s) so that the attached classified LANs can meet this requirement.

Provide or use a dedicated address space for the VVoIP system that is segregated from the address space used for the general LAN, management VLANs, and other segregated services running on the LAN.

Use this address space when configuring VVoIP VLANs and when assigning addresses to VVoIP endpoints and core equipment.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23948r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19628'
  tag rid: 'SV-21769r2_rule'
  tag stig_id: 'VVoIP 5225'
  tag gtitle: 'Deficient imp’n: VVoIP addressing re: def’d range'
  tag fix_id: 'F-20332r1_fix'
  tag 'documentable'
end
