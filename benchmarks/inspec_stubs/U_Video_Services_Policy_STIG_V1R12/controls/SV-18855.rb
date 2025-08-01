control 'SV-18855' do
  title 'Insufficient security clearance held by an “operator/facilitator/administrator” performing remote monitoring activities during a VTC session/conference.'
  desc 'Administrators or “operators/facilitators” that perform monitoring as discussed in this section must have an appropriate security clearance commensurate with or higher than the classification level of the system and/or the information to which they are exposed.'
  desc 'check', '[IP][ISDN]; Interview the Administrator to validate compliance with the following requirement:

Ensure administrators that are required to monitor a conference or conferences possess a security clearance that is the same as or higher than the VTC system and the conference information to which they are exposed. 

Verify with IAO that conference call operator/facilitator has security clearance commensurate with or higher than the classification level of the system and/or the information to which they are exposed.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:

Ensure administrators that are required to monitor a conference or conferences possess a security clearance that is the same as or higher than the VTC system and the conference information to which they are exposed.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17681'
  tag rid: 'SV-18855r1_rule'
  tag stig_id: 'RTS-VTC 1168.00'
  tag gtitle: 'RTS-VTC 1168.00 [IP][ISDN]'
  tag fix_id: 'F-17578r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a SA that is monitoring a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Information Assurance Officer', 'Other']
end
