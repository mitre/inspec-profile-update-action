control 'SV-18727' do
  title 'Inadequate “operator/facilitator/administrator” access control for remote monitoring of a VTU connected to an IP network.'
  desc 'Activation and use of remote monitoring and control features such as those discussed here and in RTS-VTC 1160.00 must be protected by access control. Minimally this must be the administrator password; however, access to this feature should not give full administrator access.'
  desc 'check', '[IP]; Interview the IAO to validate compliance with the following requirement:

In the event the VTU is connected to an IP network ensure access to IP remote monitoring and associated control functions of the VTU is minimally protected by a password. 

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU. i.e., remote monitoring must be able to have a password set in order to access remote monitoring features.

Verify that an administrator password is required to access remotely accessible VTU. Have the IAO or SA demonstrate compliance with the requirement.'
  desc 'fix', '[IP]; Perform the following tasks:
If IP remote monitoring is activated, configure the VTU to require a password before permitting access to the remote monitoring and associated control functions.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18900r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17600'
  tag rid: 'SV-18727r1_rule'
  tag stig_id: 'RTS-VTC 1162.00'
  tag gtitle: 'RTS-VTC 1162.00 [IP]'
  tag fix_id: 'F-17518r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a SA that is monitoring a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1, IAIA-1, IAIA-2'
end
