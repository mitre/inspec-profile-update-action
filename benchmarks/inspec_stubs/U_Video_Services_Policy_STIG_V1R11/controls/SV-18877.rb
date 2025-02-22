control 'SV-18877' do
  title 'SNMP is not being used in accordance with the Network Infrastructure STIG.'
  desc 'Some VTC endpoints can be monitored using SNMP. It is also possible that if not today, in the future, VTC endpoints could be configured via SNMP. SNMP is typically used by vendor’s VTU/MCU management applications but it is conceivable that SNMP traps could be sent to any SNMP compatible network management system. At the time of this writing, applicable STIG requirements for the use of SNMP are contained in the Network Infrastructure STIG.'
  desc 'check', '[IP]; Interview the IAO and validate compliance with the following requirement:
   
If SNMP is used to monitor or remotely control/manage/configure a VTC system/device, ensure the use of SNMP is performed in compliance with the applicable SNMP requirements found in the Network Infrastructure STIG.
   
This is a finding if SNMP is not being used in accordance with the Network Infrastructure STIG.
   
Note: During APL testing, this is a finding in the event SNMP configuration cannot come into compliance with the Network Infrastructure STIG.'
  desc 'fix', '[IP]; Perform the following tasks:
If SNMP is used to monitor or remotely control/manage/configure a VTC system/device, implement and configure SNMP in compliance with the applicable SNMP requirements found in the Network Infrastructure STIG.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17703'
  tag rid: 'SV-18877r1_rule'
  tag stig_id: 'RTS-VTC 3140.00'
  tag gtitle: 'RTS-VTC 3140.00 [IP]'
  tag fix_id: 'F-17600r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Improperly configured SNMP monitoring and management protocols used to monitor or control/manage/configure a VTC system/device could lead to the disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
