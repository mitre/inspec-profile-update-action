control 'SV-18878' do
  title 'Remote management access and SNMP access and reporting are not restricted by IP address and/or subnet.'
  desc 'In any network device management system, it is best practice to limit the IP address or addresses from which a network attached device can be accessed and to which device status information can be sent.'
  desc 'check', '[IP]; Interview the IAO and validate compliance with the following requirement:
   
If the VTU is connected to an IP based LAN, ensure remote management access (administrator and management system/server/application) and SNMP access and reporting is restricted by IP address and/or subnet. 
   
Determine what IP addresses or subnets are authorized to send VTC system/device “Remote Control/Management/Configuration” messages and what IP addresses or subnets are authorized to receive monitoring or status messages from the VTC system/device. Have the SA demonstrate how the VTC system/device is configured to restrict “Remote Control/Management/Configuration” messages to and from these authorized IP addresses or subnets. This is a finding if there is no limitation on either sending or receiving these messages.
   
Note: During APL testing, this is a finding in the event the VTC system/devoice does not support the limiting of all management traffic to authorized IP addresses or subnets.'
  desc 'fix', '[IP]; Perform the following tasks:
Configure the VTC system/device to restrict The source and/or destination of VTC system/device “Remote Control/Management/Configuration” and monitoring/status traffic to/from authorized IP addresses or subnets.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18974r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17704'
  tag rid: 'SV-18878r2_rule'
  tag stig_id: 'RTS-VTC 3160.00'
  tag gtitle: 'RTS-VTC 3160.00 [IP]'
  tag fix_id: 'F-17601r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Not limiting the source and/or destination of VTC system/device “Remote Control/Management/Configuration” traffic to/from authorized IP addresses could lead to the disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
