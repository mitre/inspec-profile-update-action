control 'SV-204776' do
  title 'The application server must use cryptographic mechanisms to protect the integrity of log tools.'
  desc 'Protecting the integrity of the tools used for logging purposes is a critical step in ensuring the integrity of log data. Log data includes all information (e.g., log records, log settings, and log reports) needed to successfully log information system activity. 

It is not uncommon for attackers to replace the log tools or inject code into the existing tools for the purpose of providing the capability to hide or erase system activity from the logs. 

To address this risk, log tools must be cryptographically signed in order to provide the capability to identify when the log tools have been modified, manipulated or replaced. An example is a checksum hash of the file or files.

Application server log tools must use cryptographic mechanisms to protect the integrity of the tools or allow cryptographic protection mechanisms to be applied to their tools.'
  desc 'check', 'Review the application server configuration to determine if the application server log tools have been cryptographically signed to protect the integrity of the tools.

If the application server log tools have not been cryptographically signed, this is a finding.'
  desc 'fix', 'Configure the application server log tools to be cryptographically signed to protect the integrity of the tools.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4896r282975_chk'
  tag severity: 'medium'
  tag gid: 'V-204776'
  tag rid: 'SV-204776r508029_rule'
  tag stig_id: 'SRG-APP-000290-AS-000174'
  tag gtitle: 'SRG-APP-000290'
  tag fix_id: 'F-4896r282976_fix'
  tag 'documentable'
  tag legacy: ['V-35445', 'SV-46732']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
