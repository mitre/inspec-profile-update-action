control 'SV-18856' do
  title 'Far end camera control is not disabled.'
  desc 'Many VTC endpoints support Far End Camera Control (FECC). This feature uses H.281 protocol which must be supported by both VTUs. Typically, this is only available during an active VTC session but could be available if the VTU is compromised or if a call is automatically answered. Allowing another conference attendee to take control of your camera can place the confidentiality of non conference related information at risk. FECC should be disabled to prevent the control of the near end camera by the far end unless required to satisfy validated mission requirements.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

Ensure far end camera control is disabled unless required to satisfy validated, approved, and documented mission requirements. 

Note: The documented and validated mission requirements along with their approval(s) are maintained by the IAO for inspection by auditors. Such approval is obtained from the DAA or IAM responsible for the VTU(s) or system. 

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU. i.e., far end camera control must be able to be disabled or the feature must not be supported.

Determine if remote monitoring is required and approved to meet mission requirements. Have the IAO or SA demonstrate compliance with the requirement.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Configure the CODEC to disable far end camera control
OR
Document and validate the mission requirements that require far end camera control to be enabled and obtain DAA approval. Maintain the requirement and approval documentation for review by auditors.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18952r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17682'
  tag rid: 'SV-18856r1_rule'
  tag stig_id: 'RTS-VTC 1180.00'
  tag gtitle: 'RTS-VTC 1180.00 [IP][ISDN]'
  tag fix_id: 'F-17579r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
