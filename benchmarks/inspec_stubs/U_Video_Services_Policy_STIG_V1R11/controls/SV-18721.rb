control 'SV-18721' do
  title 'Inadequate display of an incoming call notification such that the VTU user can make an informed decision to answer the call or not.'
  desc 'In the event that mission requirements dictate the VTU be in a powered-on state when inactive the VTU becomes available to receive incoming calls (except possibly when sleeping). Additionally, if a VTU is connected to an IP network, it may be capable of receiving incoming calls while active. When a VTU receives an incoming call; the normal operation is that a notification of the incoming call is provided both audibly and visually. The visual notification typically includes a display of the source of the call. This can be a phone number or IP address. This information should be accompanied by an identification of the caller. While the source information is typically available from the network, the identity of the calling party associated with that information is typically contained in a locally accessible directory. If the source information is in the directory, the associated identity information is located and added to the display or displayed by itself. This directory is typically on the VTU or can be on a locally associated management or directory server. Directories must therefore be kept up to date with user information related to other VTUs with which any given VTU is expected to communicate. Ideally, the full identity of the caller is sent from the calling system for display on the called system even if there is no local directory entry. 

Based upon the displayed information, the user of the VTU can make an informed decision and take appropriate action to answer the call, or not. Users must be trained to not answer calls from unknown sources in the event doing so could disclose sensitive or classified information in the area of the VTU or while engaged in a VTC session.'
  desc 'check', '[IP][ISDN] Interview the IAO to validate for compliance with the following requirement:

If the VTU is capable of receiving incoming calls while inactive or while active, ensure the following: 

- The VTU displays the source of the incoming call and to the extent possible, the identity of the caller, such that the user can make an informed decision to answer the call or not. 
- Directories are maintained with current information regarding user information related to other VTUs with which the VTU is expected to communicate unless calling VTUs provide the caller information along with the source information. 
- Users are trained to not answer incoming calls from unknown sources in the event doing so could disclose sensitive or classified information in the area of the VTU. 
- Users are trained to not answer incoming calls from unknown sources or sources that may not have appropriate clearance or a need-to-know during a conference since doing so could improperly disclose sensitive or classified information to the caller. 

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU.

Interview the IAO and have him/her demonstrate on a sampling of the VTUs in the system'
  desc 'fix', '[IP][ISDN];  Perform the following tasks:

- Configure the VTU to display the source of the incoming call and to the extent possible, the identity of the caller, such that the user can make an informed decision to answer the call or not. 
- Maintained directories with current information regarding user information related to other VTUs with which the VTU is expected to communicate unless calling VTUs provide the caller information along with the source information. 
- Train users to not answer incoming calls from unknown sources in the event doing so could disclose sensitive or classified information in the area of the VTU. 
- Train users to not answer incoming calls from unknown sources or sources that may not have appropriate clearance or a need-to-know during a conference since doing so could improperly disclose sensitive or classified information to the caller.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18894r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17594'
  tag rid: 'SV-18721r1_rule'
  tag stig_id: 'RTS-VTC 1030.00'
  tag gtitle: 'RTS-VTC 1030.00 [IP][ISDN]'
  tag fix_id: 'F-17512r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
