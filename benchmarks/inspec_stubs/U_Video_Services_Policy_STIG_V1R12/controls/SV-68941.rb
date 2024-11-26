control 'SV-68941' do
  title 'Video teleconferencing system components Standard Mandatory DoD Notice and Consent Banner must be acknowledged by the user prior to logon or initial access.'
  desc 'The operating system and remotely accessed information systems are required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met. 

System use notification messages must be displayed when individuals log on to the information system. The approved DoD text must be used as specified in the DoD Instruction 8500.01 dated March 14, 2014.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Verify all video teleconferencing system components retain the Standard Mandatory DoD Notice and Consent Banner on the screen until acknowledgement of the usage conditions by taking explicit actions to log on for further access.'
  desc 'fix', 'Configure all video teleconferencing system components to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until acknowledgement of the usage conditions by taking explicit actions to log on for further access.'
  impact 0.3
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-55317r2_chk'
  tag severity: 'low'
  tag gid: 'V-54695'
  tag rid: 'SV-68941r1_rule'
  tag stig_id: 'RTS-VTC 3425.00'
  tag gtitle: 'RTS-VTC 3425'
  tag fix_id: 'F-59551r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECWM-1'
end
