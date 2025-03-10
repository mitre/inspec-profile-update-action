control 'SV-8790' do
  title 'Customers of the DISN VoSIP service on ARE NOT utilizing address blocks assigned by the DRSN / VoSIP PMO.'
  desc 'A previous requirement states the following: Ensure a different, dedicated, address blocks or ranges are defined for the VVoIP system within the LAN (Enclave) that is separate from the address blocks/ranges used by the rest of the LAN for non VVoIP system devices thus allowing traffic and access control using firewalls and router ACLs. 
NOTE: This is applicable to the following: > A classified LAN connected to a classified WAN (such as the SIPRNet). 

NOTE: In the case of a classified WAN where network wide address based accountability or traceability is required by the network PMO, the PMO must provide a segregated, network wide address block(s) so that the attached classified LANs can meet this requirement. DISA provides a world wide VoIP based voice communications service called the DISN Voice over Secret IP (VoSIP) service or just VoSIP for short. This service is managed by the DRSN PMO. This service also provides gateways into the DRSN. In support of the above requirement, the SIPRNet PMO has designated specific dedicated address ranges for use by the DISN VoSIP service and assigned these address blocks to the DRSN/VoSIP PMO for VoSIP address management and assignment. The VoSIP service provides VoIP based communications between VoIP systems within customer’s classified LANs (C-LANs) operating at the secret level while using the SIPRNet WAN for the inter-enclave (inter-LAN) transport. Additionally, the SIPRNet PMO requires network wide address based accountability or traceability based on assigned IP address. As such customer’s SIPRNet connected secret C-LANs utilize addresses assigned by the SIPRNet PMO. Therefore, customers of the DISN VoSIP service must use IP addresses assigned to them by the DRSN/VoSIP PMO when addressing the VoIP controllers and endpoints within their C-LANs. This is to maintain the segregation of the Voice and data environments on the customer’s secret C-LANs as required by this STIG. This also facilitates proper routing and flow control over the traffic between VoSIP addresses. 

NOTE: the DISN service is designated DISN Voice over Secret IP but uses an acronym (VoSIP) which also means Voice over Secure IP. Voice over Secure IP relates to any VoIP based service on a secure or classified IP network. 

NOTE: While the DISN VoSIP service is the preferred means to interconnect SIPRNet connected secret C-LANs for VoIP service, it is recognized that there may be a need for an organization to implement a VoIP based voice or video communications system within their organization or with close partners. In the event such a system has no need or potential need to communicate with other enclaves that use the DISN VoSIP service, they must utilize their own dedicated IP address space carved out of the address space assigned to their C-LANs by the SIPRNet PMO in accordance with the previously noted requirement.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

Ensure customers of the DISN VoSIP service use IP addresses assigned to them by the DRSN/VoSIP PMO when defining the required dedicated address space for the VoIP controllers and endpoints within their secret C-LANs.

NOTE: This is similarly applicable to other classified DISN services and customer’s C-LANs.
NOTE: This is not a requirement in the event a VoIP based VVoIP communications system operated in a secret C-LAN has no need or potential need to use the worldwide DISN VoSIP service or have access the DRSN and communicate with other enclaves that do use the DISN service or have access the DRSN, they must utilize their own dedicated IP address space carved out of the address space assigned to their C-LANs by the SIPRNet PMO in accordance with the previously noted requirement.

NOTE: This requirement does not directly apply to dedicated hardware based IP - VTC systems using the C-LAN and SIPRNet for transport although there may be similar requirements to address this technology in the future.

Determine the following:
Is the organization’s secret C-LAN connected to SIPRNet?
Does the organization’s secret C-LAN support VVoIP communications (Not dedicated IP based VTC)?
Does organization’s secret C-LAN VVoIP system interconnect with other enclaves using the DISN VoSIP service?
What address blocks are dedicated to the VVoIP system on the C-LAN?
Is there documented evidence that the DRSN/VoSIP PMO assigned these addresses to the organization or can such assignment be validated by other means?

This is a finding in the event the organization’s secret C-LAN supports VVoIP communications (Not dedicated IP based VTC) AND is connected to SIPRNet AND uses the DISN VoSIP service BUT DOES NOT use the DRSN/VoSIP PMO assigned address blocks when addressing all of the VVoIP system components.'
  desc 'fix', 'Ensure customers of the DISN VoSIP service use IP addresses assigned to them by the DRSN/VoSIP PMO when defining the required dedicated address space for the VoIP controllers and endpoints within their secret C-LANs.
NOTE: This is similarly applicable to other classified DISN services and customer’s C-LANs.

NOTE: This is not a requirement in the event a VoIP based VVoIP communications system operated in a secret C-LAN has no need or potential need to use the worldwide DISN VoSIP service or have access the DRSN and communicate with other enclaves that do use the DISN service or have access the DRSN, they must utilize their own dedicated IP address space carved out of the address space assigned to their C-LANs by the SIPRNet PMO in accordance with the previously noted requirement.

NOTE: This requirement does not directly apply to dedicated hardware based IP - VTC systems using the C-LAN and SIPRNet for transport although there may be similar requirements to address this technology in the future.

Obtain and assign IP addresses as provided by the DRSN PMO- VoSIP department when defining the required dedicated address space on the LAN.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23794r1_chk'
  tag severity: 'low'
  tag gid: 'V-8295'
  tag rid: 'SV-8790r1_rule'
  tag stig_id: 'VVoIP 5215 (LAN)'
  tag gtitle: 'Deficient design: VVoIP addressing re: DISN VoSIP'
  tag fix_id: 'F-20240r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Denial of service; Lack of interoperability with other VoSIP enclaves'
  tag responsibility: 'Information Assurance Officer'
end
