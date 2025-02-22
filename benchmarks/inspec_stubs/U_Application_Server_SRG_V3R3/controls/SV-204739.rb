control 'SV-204739' do
  title 'The application server must use cryptographic mechanisms to protect the integrity of log information.'
  desc 'Protecting the integrity of log records helps to ensure log files are not tampered with. Cryptographic mechanisms are the industry-established standard used to protect the integrity of log data. An example of cryptographic mechanisms is the computation and application of a cryptographic hash and using asymmetric cryptography with digital signatures.  Application Servers often write log data to files on the file system.  These files typically roll over on a periodic basis. Once the logs are rolled over, hashing and signing the logs assures the logs are not tampered with and helps to assure log integrity.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server can be configured to protect the integrity of log data using cryptographic hashes and digital signatures. Configure the application server to hash and sign log data. This is typically done the moment when log files cease to be written to and are rolled over for storage or offloading. 

Alternatively, if the application server is not able to hash and sign log data, the task can be delegated by configuring the application server or underlying OS to send logs to a centralized log management system or SIEM that can meet the requirement. 

If the application server is not configured to hash and sign logs, or is not configured to utilize the aforementioned OS and centralized log management resources to meet the requirement, this is a finding.'
  desc 'fix', 'Configure the application server to hash and sign logs using cryptographic means. 

Alternatively, configure the application server or OS to send logs to a centralized log server that meets the hashing and signing requirement.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4859r282864_chk'
  tag severity: 'medium'
  tag gid: 'V-204739'
  tag rid: 'SV-204739r508029_rule'
  tag stig_id: 'SRG-APP-000126-AS-000085'
  tag gtitle: 'SRG-APP-000126'
  tag fix_id: 'F-4859r282865_fix'
  tag 'documentable'
  tag legacy: ['V-35217', 'SV-46504']
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
end
