control 'SV-102615' do
  title 'Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.'
  desc "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files."
  desc 'check', 'Review the web server documentation and configuration to determine what web server accounts are available on the server.

If any directories or files are owned by anyone other than root, this is a finding.

If non-privileged web server accounts are available with access to functions, directories, or files not needed for the role of the account, this is a finding.'
  desc 'fix', 'Limit the functions, directories, and files that are accessible by each account and role to administrative accounts and remove or modify non-privileged account access.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92527'
  tag rid: 'SV-102615r1_rule'
  tag stig_id: 'AS24-W2-000430'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-98769r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
