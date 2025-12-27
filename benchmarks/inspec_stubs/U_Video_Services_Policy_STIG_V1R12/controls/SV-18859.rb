control 'SV-18859' do
  title 'VTU encryption indicator is not enabled.'
  desc 'In support of the need for encryption and the need for the VTU user to be aware that in fact his/her conference session is being encrypted, the VTU must display an indicator that encryption is indeed occurring.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

Ensure all VTU’s under IAO’s control display a visual indicator that encryption is in fact taking place.

Note: During APL testing, this is a finding in the event this requirement is not supported by the CODEC i.e., an on screen visual indicator displaying that encryption is indeed occurring.

Note: In the event encryption is provided by external devices (not the CODEC), an external indicator meets this requirement in place of the on-screen indicator.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:

Implement VTU CODECs that provide an on screen indicator that encryption is occurring and active.
OR
If the encryption is provided by external devices (not the CODEC), implement an external indicator to display encryption status in place of an on-screen indicator provided by the CODEC.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17685'
  tag rid: 'SV-18859r1_rule'
  tag stig_id: 'RTS-VTC 1250.00'
  tag gtitle: 'RTS-VTC 1250.00 [IP][ISDN]'
  tag fix_id: 'F-17582r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This is not a finding in the event encryption is provided by external devices (not the CODEC), AND an external indicator is used to display encryption status in place of an on-screen indicator provided by the CODEC.'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
