control 'SV-18860' do
  title 'Deficient SOP or enforcement for user validation that encryption is on when required'
  desc 'When encryption is enabled via automatic/negotiate, and one endpoint does not support encryption or supports DES and not AES, the entire conference defaults to the lower capability level. This is not acceptable for some conferences depending upon the sensitivity of the information discussed or presented. As noted above, the stated DoD IA controls require encryption. To ensure this requirement is met, when it is unknown whether all endpoints in a conference support encryption and whether it is turned on, the VTU user must provide the final check that encryption is being used. If a conference is to be encrypted, the user must check that all participants are using encryption and have enabled the encryption on their devices. When the conference has begun, the user must ensure that the conference is encrypted. The alternate to this is to exclude the endpoint that does not support the required encryption or not proceed with the conference session.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

Ensure a policy and procedure is in place and enforced that addresses user activation and verification of encryption use when encryption is required based on the sensitivity of the information discussed or presented. The following must be included:
- The user must check that all participants are using encryption and have enabled the encryption on their devices if manual activation necessary.
- When the conference has begun, the user must ensure that the VTU is displaying the “conference is encrypted” indication.
Note: This requirement must be reflected in user training, agreements and guides.

Verify that there is a policy and procedure in place that enforces and guides users on how and what to check when participants are required to use encryption.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Define and enforce policy and procedure that addresses user activation and verification of encryption use when encryption is required based on the sensitivity of the information discussed or presented. The following must be included:
- The user must check that all participants are using encryption and have enabled the encryption on their devices if manual activation necessary.
- When the conference has begun, the user must ensure that the VTU is displaying the “conference is encrypted” indication.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18956r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17686'
  tag rid: 'SV-18860r1_rule'
  tag stig_id: 'RTS-VTC 1260.00'
  tag gtitle: 'RTS-VTC 1260.00 [IP][ISDN]'
  tag fix_id: 'F-17583r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
end
