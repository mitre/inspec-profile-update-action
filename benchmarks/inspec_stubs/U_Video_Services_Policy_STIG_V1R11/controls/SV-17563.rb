control 'SV-17563' do
  title 'Deficient SOP or enforcement for VTC/CODEC streaming.'
  desc 'To control streaming from a VTU/CODEC, the site must have a policy and procedure regarding the use of streaming. This could be very simple if streaming will never be used or more complex if there is the potential for its use. Such an SOP will reflect the requirements of this STIG regarding streaming. 

Note: For additional information regarding the vulnerabilities associated with VTC streaming, see the discussion under RTS-VTC 2340'
  desc 'check', '[IP]; Interview the IAO to validate compliance with the following requirement:

In the event the VTU/CODEC is connected to an IP based LAN, and if the CODEC supports streaming, ensure a “Streaming” policy and procedure is in place and enforced that addresses the following:
- The approval of conference streaming on a case by case basis prior to it being configured by an administrator and activated. 
- Implementation and distribution of temporary one-time “streaming passwords”, and other session information, to control recipient access to the media stream. For best protection of the system, this password must be used one time and not repeated. This password must not match any other user or administrative password and must be configured to meet or exceed DoD password complexity requirements since entry from a keyboard is expected. 
- Requirements for implementing an appropriate streaming configuration to limit the reach of the stream across the network.
- Re installation of the “blocking” configuration and password (as required below) following any given streaming session. 
- Changes to the “access blocking” configuration and password in the event it is compromised or if administrative staff changes.

Note: The details of this SOP will be included in user’s training, agreements, and guides.
    
Note: This is a requirement whether streaming from a CODEC is approved or not.

Inspect the SOP as well as user training materials, agreements, and guides to determine if the items in the requirement are adequately covered. Interview the IAO to determine how the SOP is enforced. Interview a sampling of users to determine their awareness and implementation of the requirement and whether the SOP is enforced. This is a finding if deficiencies are found in any of these areas. Note the deficiencies in the finding details.'
  desc 'fix', '[IP]; If the CODEC supports streaming, Perform the following tasks:
- Develop and enforce the SOP, train users, and include the SOP in user agreements and guides. 
- The SOP will address the following:
> The approval of conference streaming on a case by case basis prior to it being configured by an administrator and activated. 
> Implementation and distribution of temporary “streaming passwords”, or other session information, to control recipient access to the media stream. For best protection of the system, this password must be used one time and not repeated. This password must not match any other user or administrative password and must be configured to meet or exceed DoD password complexity requirements since entry from a keyboard is expected. A temporary, one time password is implemented during streaming enablement and configuration of the given streaming session. 
> Requirements for implementing an appropriate streaming configuration to limit the reach of the stream across the network.
> Re installation of the “blocking” configuration and password (as required below) following any given streaming session. 
> Changes to the “access blocking” configuration and password in the event it is compromised or if administrative staff changes.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-17362r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16564'
  tag rid: 'SV-17563r2_rule'
  tag stig_id: 'RTS-VTC 2360.00'
  tag gtitle: 'RTS-VTC 2360.00 [IP]'
  tag fix_id: 'F-16534r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent or improper disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
  tag ia_controls: 'DCBP-1, ECSC-1, IAAC-1, IAIA-1, IAIA-2'
end
