control 'SV-18869' do
  title 'CODEC streaming is not disabled when it is not required.'
  desc 'When a CODEC is not required to be streaming, the capability will be disabled. The preferred method for this is via an administrator configurable setting. Both user activation and remote start must be addressed. In lieu of this, a streaming configuration must be implemented on the VTU that inhibits the ability to stream such that streaming will not be able to effectively be used to view a room or conference.

Note: For additional information regarding the vulnerabilities associated with VTC streaming, see the discussion under RTS-VTC 2340'
  desc 'check', '); [IP]; Interview the IAO to validate compliance with the following requirement:

Ensure the following streaming configuration settings are implemented as prudent to further minimize the effect of accidental or unwanted streaming activation when streaming is not required to be activated:
- Disable streaming and/or user activation of streaming
- Disable remote start of streaming (if remote start is supported) 
OR if the above settings do not exist or do not work properly: 
- Clear the streaming destination or multicast address(s)
- Set TTL/router hops to 0 or a maximum of 1 if 0 is not accepted.
- Set the password used to access the CODEC for streaming to a strong password that meets or exceeds minimum DoD password requirements. This password is kept confidential. 

Note: If clearing the IP address or IP port does not prevent the CODEC from streaming to a default address or port, set a unicast addresses that will never be used by a device and set a very high IP port. 
    
Note: This requirement is applicable whether the CODEC is normally connected to an IP based LAN or not. If not normally connected to an IP based LAN, these settings will mitigate the vulnerability in the event the CODEC does become connected to a LAN via un-authorized or clandestine means
    
Note: During APL testing, this is a finding in the event the product does not support the ability to disable conference streaming.

Have the IAO or SA demonstrate the streaming configuration on a random sampling of CODECs.'
  desc 'fix', '[IP]; Perform the following tasks when CODEC streaming is not required to be use:
Configure the CODEC as follows:
- Disable streaming and/or user activation of streaming
- Disable remote start of streaming (if remote start is supported) 
OR if the above settings do not exist or do not work properly: 
- Clear the streaming destination or multicast address(s)
- Set TTL/router hops to 0 or a maximum of 1 if 0 is not accepted.
- Set the password used to access the CODEC for streaming to a strong password that meets or exceeds minimum DoD password requirements. This password is kept confidential. 
    
Note: If clearing the IP address or IP port does not prevent the CODEC from streaming to a default address or port, set a unicast addresses that will never be used by a device and set a very high IP port. 
    
Note: This requirement is applicable whether the CODEC is normally connected to an IP based LAN or not. If not normally connected to an IP based LAN, these settings will mitigate the vulnerability in the event the CODEC does become connected to a LAN via un-authorized or clandestine means'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18965r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17695'
  tag rid: 'SV-18869r1_rule'
  tag stig_id: 'RTS-VTC 2380.00'
  tag gtitle: 'RTS-VTC 2380.00 [IP]'
  tag fix_id: 'F-17592r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent or improper disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
