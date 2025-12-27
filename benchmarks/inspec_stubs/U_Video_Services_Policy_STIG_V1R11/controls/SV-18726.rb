control 'SV-18726' do
  title 'Remote monitoring is not disabled while connected to an IP Network.'
  desc 'Some VTC endpoints support the capability for an administrator or facilitator to view or monitor the VTU location (i.e., the room where it is located) remotely via a web interface. Some VTUs provide this feature via snapshots, while others provide the capability in real time. This feature can also include control capabilities and is used for troubleshooting, checking endpoints and rooms for operational readiness, or active monitoring of a call for quality control, etc. This capability poses a confidentiality issue for active conferences and the information in the proximity of the endpoints. Remote monitoring must be disabled as a general rule unless required to satisfy validated and approved mission requirements to prevent unauthorized access. This discussion also applies to administrator’s endpoints fully participating in a call for reasons of troubleshooting or quality control.'
  desc 'check', '[IP]; Interview the IAO to validate compliance with the following requirement:

In the event the VTU is connected to an IP network ensure remote monitoring of the VTU via IP is disabled unless required to satisfy validated, approved, and documented mission requirements. 

Note: The documented and validated mission requirements along with their approval(s) are maintained by the IAO for inspection by auditors. Such approval is obtained from the DAA or IAM responsible for the VTU(s) or system. 

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU. i.e., remote monitoring must be able to be disabled or the feature/capability must not be supported.

Interview the IAO to determine if remote monitoring is required and approved to meet mission requirements. Have the IAO or SA demonstrate compliance with the requirement.'
  desc 'fix', '[IP]; Perform the following tasks:
- Obtain validation of mission requirements and DAA approval if remote monitoring of a VTU is to be used. 
OR 
- Configure the VTU to disable remote monitoring if the feature is not needed to satisfy validated, approved, and documented mission requirements.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17599'
  tag rid: 'SV-18726r1_rule'
  tag stig_id: 'RTS-VTC 1160.00'
  tag gtitle: 'RTS-VTC 1160.00 [IP]'
  tag fix_id: 'F-17517r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a SA that is monitoring a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1, PEDI-1'
end
