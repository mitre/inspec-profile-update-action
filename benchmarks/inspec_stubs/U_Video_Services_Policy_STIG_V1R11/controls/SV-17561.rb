control 'SV-17561' do
  title 'No indicator is displayed on the VTU screen when CODEC streaming is activated.'
  desc 'It is imperative that the operator of a VTU know if his/her CODEC is streaming. This is due the ease with which streaming can be activated accidentally or intentionally and that it can be activated remotely by various methods or individuals with different privilege levels. The VTU must display an indication on the screen if it is actively streaming so that the VTU user/operator can be aware of the fact and take action to stop the streaming or disconnect the call if the CODEC should not be streaming.

Note: For additional information regarding the vulnerabilities associated with VTC streaming, see the discussion under RTS-VTC 2340'
  desc 'check', '[IP]; Validate compliance with the following requirement:
    
Ensure an on-screen indicator is displayed when the VTU/CODEC is actively streaming. Include awareness of the indicator and its meaning in user training and user guides.
    
Note: This is a requirement whether streaming from a CODEC is approved or not.
    
Note: During APL testing, this is a finding in the event this requirement is not supported by the CODEC.
    
This is a finding if an on-screen indicator is not displayed when the VTU/CODEC is actively streaming. Validate compliance via inspection of the device manuals or activate streaming and look for the on-screen indicator.  Activating the streaming feature may require applying a streaming configuration. If so, be sure to remove/disable the configuration following the indicator test.'
  desc 'fix', '[IP]; Perform the following tasks:
- Purchase VTC equipment that either does not support streaming from the CODEC or provides an indicator that the CODEC is actively streaming.
AND/OR
- Configure the CODEC to provide the required on-screen indicator in the event such display does not occur by default.
AND
Include awareness of the indicator and its meaning in user training and user guides.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-17361r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16562'
  tag rid: 'SV-17561r1_rule'
  tag stig_id: 'RTS-VTC 2350.00'
  tag gtitle: 'RTS-VTC 2350.00 [IP]'
  tag fix_id: 'F-16532r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent or improper disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Other', 'System Administrator']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
