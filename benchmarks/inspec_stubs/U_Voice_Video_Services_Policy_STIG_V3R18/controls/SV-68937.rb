control 'SV-68937' do
  title 'VVoIP system components and UC soft clients must display the Standard Mandatory DoD Notice and Consent Banner exactly as specified prior to logon or initial access.'
  desc 'The operating system and remotely accessed information systems are required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met. 

System use notification messages must be displayed when individuals log in to the information system. The approved DoD text must be used as specified in the DoD Instruction 8500.01 dated March 14, 2014.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement:

Verify all VVoIP system components and UC soft clients display the Standard Mandatory DoD Notice and Consent Banner prior to logon or initial access. If the displayed text is not exactly as specified in the DoD Instruction 8500.01 dated March 14, 2014, this is a finding.

The text is posted on the IASE website:
http://iase.disa.mil/Documents/unclass-consent_banner.zip'
  desc 'fix', 'Configure all VVoIP system components and UC soft clients to display the Standard Mandatory DoD Notice and Consent Banner prior to logon or initial access.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-55311r2_chk'
  tag severity: 'low'
  tag gid: 'V-54691'
  tag rid: 'SV-68937r1_rule'
  tag stig_id: 'VVoIP 1340'
  tag gtitle: 'Display DoD Notice and Consent Banner'
  tag fix_id: 'F-59547r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECWM-1'
end
