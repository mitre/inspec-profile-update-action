control 'SV-18876' do
  title 'Unnecessary/unused remote control/management/configuration protocols are not disabled.'
  desc 'Management or other protocols, secure or not, that are not required or used for management of, or access to, a device in a given implementation, but are active and available for a connection, places the device at risk of compromise and unauthorized access. These protocols must be disabled or turned off.'
  desc 'check', '[IP]; Interview the IAO and validate compliance with the following requirement:
    
Ensure remote access ports, protocols, and services used for VTC system/device “Remote Control/Management/Configuration” are disabled, turned off, or removed if not required in the specific implementation of the device.
    
Determine what ports, protocols, and services are required for in the specific implementation of the device. Have the SA demonstrate the device configuration regarding these protocols or independently validate that only the required ports, protocols, and services are active. Validation can be performed by performing a scan of the network and management interface of the system/device. This is a finding if it is determined that there are ports, protocols, and services active that are not needed for the specific implementation of the device.'
  desc 'fix', '[IP]; Perform the following tasks:
Configure the VTC system/device such that unused or unneeded ports, protocols, and services are disabled or removed from the system.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18972r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17702'
  tag rid: 'SV-18876r1_rule'
  tag stig_id: 'RTS-VTC 3130.00'
  tag gtitle: 'RTS-VTC 3130.00 [IP]'
  tag fix_id: 'F-17599r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The availability of unused or unneeded ports, protocols, and services used to configure and manage or otherwise access a VTC system/device could lead to the disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
