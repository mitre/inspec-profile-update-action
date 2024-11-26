control 'SV-18882' do
  title 'Deficient SOP or enforcement regarding the approval and deployment of VTC capabilities.'
  desc 'Due to the various IA issues surrounding VTC endpoint operation, they should only be installed or deployed where there is a validated requirement for their use. Conference room systems are easily justified and beneficial to an organization. General deployment to every desk in an organization is more difficult to justify. Deployments of office-based VTUs, desktop VTUs, and PC software based VTC applications must be considered on the basis of a validated need for the user to have this capability. Such needs should be revalidated annually
      
In general, when VTC systems are implemented, consideration must be given to mission benefit weighed against the operational risks and the possibility of improper disclosure of information as discussed throughout this document. While this is important for ISDN only connected VTUs, this is most important for IP connected VTUs.
      
The site must develop policies and enforce them regarding the deployment of VTC endpoints in support of IA control DCSD-1, which requires IA documentation be maintained, and IA control DCPR-1 which requires a change management process be instituted.'
  desc 'check', '[IP][ISDN]; Interview the IAO and validate compliance with the following requirement:
      
Ensure local policies are developed and enforced regarding the approval and deployment of office-based VTUs, desktop VTUs, and PC software based VTC applications. Such policies  will include and/or address the following:
- Validation and justification of the need for VTC endpoint installation to include annual revalidation.
- Approval of VTC endpoint deployment on a case by case basis.
- Documentation regarding the validation, justification, and approvals.
      
Inspect the documentation regarding the policy for justifying the installation of office-based VTUs, desktop VTUs, and PC software based VTC applications. Inspect the documentation regarding the justification and re-justification of the need for all VTC endpoint installations.  This is a finding if there is no documented policy, or if installation justifications have not been documented.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
- Develop, document and enforce a policy regarding the justification for the installation of office-based VTUs, desktop VTUs, and PC software based VTC applications
- Document the justification for the installation of all office-based VTUs, desktop VTUs, and PC software based VTC applications
- Maintain this documentation for inspection by auditors.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18978r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17708'
  tag rid: 'SV-18882r2_rule'
  tag stig_id: 'RTS-VTC 3620.00'
  tag gtitle: 'RTS-VTC 3620.00 [IP][ISDN]'
  tag fix_id: 'F-17605r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Without a local policy giving guidance to proper use and deployment of office-based VTUs, desktop VTUs, and PC software based VTC applications could lead to the disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECND-1'
end
