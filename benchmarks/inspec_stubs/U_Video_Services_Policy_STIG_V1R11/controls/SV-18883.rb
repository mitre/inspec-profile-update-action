control 'SV-18883' do
  title 'A VTC management system or endpoint must have risk approval and acceptance in writing by the responsible Authorizing Official (AO).'
  desc 'The risk of operating any DoD system or application must be assessed, defined, and formally accepted before use. The person responsible for the enclave’s network and system’s or application’s accreditation is the AO. The AO must approve changes to an existing system or the implementation of a new system having an affect the IA posture and accreditation of a system. 

The IA issues surrounding the use of VTC endpoints warrant AO approval. The AO must be made aware of the issues and vulnerabilities presented to the network, the area, and information processed as well as the mitigations for same.

The AO approval for the addition of IP based VTC endpoints or VTC infrastructure devices (MCUs, gatekeepers, gateways etc.) to the base network or organization’s intranet. This is not intended to require separate approval for each individual endpoint in a multi-endpoint system. However, if the system is a single endpoint, it may require an individual approval.'
  desc 'check', 'Review site documentation to confirm the VTC management system and endpoint have risk approval and acceptance in writing by the responsible AO. Inspect documentation to ensure that if VTC and VTU endpoints are in use, they have been approved by the responsible AO in writing. This documentation should reference the risk assessment performed with the AO’s acknowledgement of a full understanding of any risk, vulnerabilities, and mitigations surrounding the VTC implementation. If the VTC management system and endpoint do not have risk approval and acceptance in writing by the responsible AO, this is a finding.'
  desc 'fix', 'Implement site documentation containing the VTC management system and endpoint risk approval and acceptance in writing by the responsible AO.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18979r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17709'
  tag rid: 'SV-18883r3_rule'
  tag stig_id: 'RTS-VTC 3640.00'
  tag gtitle: 'RTS-VTC 3640'
  tag fix_id: 'F-17606r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
