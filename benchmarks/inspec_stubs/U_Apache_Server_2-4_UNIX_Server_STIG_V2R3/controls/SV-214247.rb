control 'SV-214247' do
  title 'Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.'
  desc "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files."
  desc 'check', 'Review the web server documentation and configuration to determine what web server accounts are available on the server.

Any directories or files owned by anyone other than an administrative service account is a finding. 

If non-privileged web server accounts are available with access to functions, directories, or files not needed for the role of the account, this is a finding.'
  desc 'fix', 'Limit the functions, directories, and files that are accessible by each account and role to administrative service accounts and remove or modify non-privileged account access.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15461r277001_chk'
  tag severity: 'medium'
  tag gid: 'V-214247'
  tag rid: 'SV-214247r612240_rule'
  tag stig_id: 'AS24-U1-000430'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-15459r277002_fix'
  tag 'documentable'
  tag legacy: ['SV-102759', 'V-92671']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
