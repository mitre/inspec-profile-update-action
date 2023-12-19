control 'SV-18868' do
  title 'Deficient user or administrator training regarding the vulnerabilities with, and operation of, CODEC streaming'
  desc 'In conjunction with the SOP for VTU/CODEC streaming, users must be trained in the vulnerabilities of streaming, how to recognize if their CODEC is streaming, and how to deactivate streaming if it should not be active.

Note: For additional information regarding the vulnerabilities associated with VTC streaming, see the discussion under RTS-VTC 2340'
  desc 'check', '[IP]; Interview the IAO to validate compliance with the following requirement:

In the event the VTU/CODEC is connected to an IP based LAN, and if the CODEC supports streaming, ensure users/operators and administrators of a VTU receive training regarding streaming that addresses the following:
- User awareness regarding the vulnerabilities streaming from a CODEC presents to conference confidentiality. 
- User awareness regarding accidental activation of streaming. 
- How to recognize the displayed indication provided by the VTU that it is in streaming mode.
- How to terminate streaming, particularly if the CODEC should not be streaming.
- The implementation and distribution of a temporary password for an approved CODEC streaming session using a one-time password that is not repeated and does not match any other user or administrative password.
    
Note: This is a requirement whether steaming from a CODEC is approved or not.

Interview VTC/CODEC administrators and user/operators to verify that they have received training on the vulnerabilities of streaming, recognition of CODEC streaming, and how to deactivate streaming when it is active.  Have a sampling of these individuals demonstrate their knowledge. 
.
This is a finding if deficiencies are found in any of these areas. Note the deficiencies in the finding details.'
  desc 'fix', '[IP]; In the event the VTU/CODEC is connected to an IP based LAN, and if the CODEC supports streaming, Perform the following tasks:
- Train CODEC user/operators and administrators regarding CODEC streaming addressing the following:
> User awareness regarding the vulnerabilities streaming from a CODEC presents to conference confidentiality. 
> User awareness regarding accidental activation of streaming. 
> How to recognize the displayed indication provided by the VTU that it is in streaming mode.
> How to terminate streaming, particularly if the CODEC should not be streaming.

Additionally include this information in user’s agreements and guides.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18964r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17694'
  tag rid: 'SV-18868r1_rule'
  tag stig_id: 'RTS-VTC 2365.00'
  tag gtitle: 'RTS-VTC 2365.00 [IP]'
  tag fix_id: 'F-17591r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent or improper disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Other']
  tag ia_controls: 'DCBP-1, IAAC-1, IAIA-1, IAIA-2, PRTN-1'
end
