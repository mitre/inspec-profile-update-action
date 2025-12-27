control 'SV-240809' do
  title 'tc Server VCO accounts accessing the directory tree, the shell, or other operating system functions and utilities must be administrative accounts.'
  desc "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files.

As with all secure web server installations, tc Server files and directories must be adequately protected with correct permissions."
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /usr/lib/vco/configuration/webapps

If the listed files are not owned by "vco", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

chown vco:vco <file_name>

Repeat the command for each file that was returned.

Note: Replace <file_name> for the name of the file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44042r674169_chk'
  tag severity: 'high'
  tag gid: 'V-240809'
  tag rid: 'SV-240809r879631_rule'
  tag stig_id: 'VRAU-TC-000480'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-44001r674170_fix'
  tag 'documentable'
  tag legacy: ['SV-100699', 'V-90049']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
