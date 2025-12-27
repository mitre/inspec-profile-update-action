control 'SRG-NET-000018-VVEP-00108_rule' do
  title 'The Unified Communications Endpoint must be configured to disable the Far End Camera Control feature if supported.'
  desc 'Many VTC endpoints support Far End Camera Control (FECC). This feature uses H.281 protocol, which must be supported by both VTUs. Typically, this is only available during an active VTC session but could be available if the VTU is compromised or if a call is automatically answered. Allowing another conference attendee to take control of the camera can place the confidentiality of nonconference-related information at risk. FECC should be disabled to prevent the control of the near end camera by the far end unless required to satisfy validated mission requirements.'
  desc 'check', 'Ensure far end camera control is disabled unless required to satisfy validated, approved, and documented mission requirements. 

Note: The documented and validated mission requirements along with their approval(s) are maintained by the ISSO for inspection by auditors. Such approval is obtained from the AO or ISSM responsible for the VTU(s) or system. 

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU. i.e., far end camera control must be able to be disabled or the feature must not be supported.

Determine if remote monitoring is required and approved to meet mission requirements. Have the ISSO or SA demonstrate compliance with the requirement.'
  desc 'fix', 'Perform the following tasks:
Configure the CODEC to disable far end camera control.
OR
Document and validate the mission requirements that require far end camera control to be enabled and obtain AO approval. Maintain the requirement and approval documentation for review by auditors.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000018-VVEP-00108_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000018-VVEP-00108'
  tag rid: 'SRG-NET-000018-VVEP-00108_rule'
  tag stig_id: 'SRG-NET-000018-VVEP-00108'
  tag gtitle: 'SRG-NET-000018-VVEP-00108'
  tag fix_id: 'F-SRG-NET-000018-VVEP-00108_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
