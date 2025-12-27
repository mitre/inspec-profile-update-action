control 'SV-204771' do
  title 'The application server must employ cryptographic mechanisms to ensure confidentiality and integrity of all information at rest when stored off-line.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system.

Application servers generate information throughout the course of their use, most notably, log data.  If the data is not encrypted while at rest, the data used later for forensic investigation cannot be guaranteed to be unchanged and cannot be used for prosecution of an attacker.  To accomplish a credible investigation and prosecution, the data integrity and information confidentiality must be guaranteed.

Application servers must provide the capability to protect all data, especially log data, so as to ensure confidentiality and integrity.'
  desc 'check', 'Review the application server configuration to ensure the system is protecting the confidentiality and integrity of all application server data at rest when stored off-line.

If the application server is not configured to protect all application server data at rest when stored off-line, this is a finding.'
  desc 'fix', 'Configure the application server to employ cryptographic mechanisms to ensure confidentiality and integrity of all application server data at rest when stored off-line.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4891r282960_chk'
  tag severity: 'medium'
  tag gid: 'V-204771'
  tag rid: 'SV-204771r508029_rule'
  tag stig_id: 'SRG-APP-000231-AS-000156'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-4891r282961_fix'
  tag 'documentable'
  tag legacy: ['SV-46713', 'V-35426']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
