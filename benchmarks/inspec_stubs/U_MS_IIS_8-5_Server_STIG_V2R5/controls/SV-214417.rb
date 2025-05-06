control 'SV-214417' do
  title 'IIS 8.5 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.'
  desc 'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. This is in addition to the anonymous web user account. The resources to which these accounts have access must also be closely monitored and controlled. Only the SA needs access to all the system’s capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files. The anonymous web user account must not have access to system resources as that account could then control the server.'
  desc 'check', 'Obtain a list of the user accounts with access to the system, including all local and domain accounts. 

Review the privileges to the web server for each account.

Verify with the system administrator or the ISSO that all privileged accounts are mission essential and documented.

Verify with the system administrator or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are found, this is a finding.

If undocumented non-administrator access to shell scripts and operating system functions are found, this is a finding.'
  desc 'fix', 'Ensure non-administrators are not allowed access to the directory tree, the shell, or other operating system functions and utilities.

All non-administrator access to shell scripts and operating system functions must be mission essential and documented.'
  impact 0.7
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15627r310299_chk'
  tag severity: 'high'
  tag gid: 'V-214417'
  tag rid: 'SV-214417r879631_rule'
  tag stig_id: 'IISW-SV-000131'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-15625r310300_fix'
  tag 'documentable'
  tag legacy: ['SV-91415', 'V-76719']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
