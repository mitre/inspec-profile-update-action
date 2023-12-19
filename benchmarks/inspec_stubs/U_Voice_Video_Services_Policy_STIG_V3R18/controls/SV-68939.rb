control 'SV-68939' do
  title 'VVoIP system components and UC soft clients Standard Mandatory DoD Notice and Consent Banner must be acknowledged by the user prior to logon or initial access.'
  desc 'The operating system and remotely accessed information systems are required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met. 

System use notification messages must be displayed when individuals log in to the information system. The approved DoD text must be used as specified in the DoD Instruction 8500.01 dated March 14, 2014.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement:

Verify all VVoIP system components and UC soft clients retain the Standard Mandatory DoD Notice and Consent Banner on the screen until acknowledgement of the usage conditions by taking explicit actions to log on for further access.'
  desc 'fix', 'Configure all VVoIP system components and UC soft clients to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until acknowledgement of the usage conditions by taking explicit actions to log on for further access.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-55313r3_chk'
  tag severity: 'low'
  tag gid: 'V-54693'
  tag rid: 'SV-68939r1_rule'
  tag stig_id: 'VVoIP 1345'
  tag gtitle: 'Acknowledge DoD Notice and Consent Banner'
  tag fix_id: 'F-59549r2_fix'
  tag 'documentable'
end
