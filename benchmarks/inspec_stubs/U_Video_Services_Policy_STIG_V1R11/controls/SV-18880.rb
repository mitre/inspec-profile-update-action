control 'SV-18880' do
  title 'Video Teleconferencing system components must display the Standard Mandatory DoD Notice and Consent Banner exactly as specified prior to logon or initial access.'
  desc 'The operating system and remotely accessed information systems are required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met. 

System use notification messages must be displayed when individuals log on to the information system. The approved DoD text must be used as specified in the DoD Instruction 8500.01 dated March 14, 2014.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Verify all video teleconferencing system components display the Standard Mandatory DoD Notice and Consent Banner prior to logon or initial access. If the displayed text is not exactly as specified in the DoD Instruction 8500.01 dated March 14, 2014, this is a finding.

The text is posted on the IASE website:
https://dl.cyber.mil/hidden/home/unclass-consent_banner.zip'
  desc 'fix', 'Configure all video teleconferencing system components to display the Standard Mandatory DoD Notice and Consent Banner prior to logon or initial access.'
  impact 0.3
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18976r3_chk'
  tag severity: 'low'
  tag gid: 'V-17706'
  tag rid: 'SV-18880r3_rule'
  tag stig_id: 'RTS-VTC 3420.00'
  tag gtitle: 'RTS-VTC 3420'
  tag fix_id: 'F-17603r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
