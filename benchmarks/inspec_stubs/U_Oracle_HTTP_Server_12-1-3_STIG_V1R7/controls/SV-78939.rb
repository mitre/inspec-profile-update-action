control 'SV-78939' do
  title 'OHS accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.'
  desc "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files."
  desc 'check', '1. Get list of OS accounts, with associated privileges, from System Administrator.

2. Confirm that all accounts and privileges are needed and documented.

3. If not, this is a finding.'
  desc 'fix', 'Remove any accounts and privileges that are unnecessary for OHS to run or for other functionality provided by the server.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65201r1_chk'
  tag severity: 'high'
  tag gid: 'V-64449'
  tag rid: 'SV-78939r1_rule'
  tag stig_id: 'OH12-1X-000266'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-70379r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
