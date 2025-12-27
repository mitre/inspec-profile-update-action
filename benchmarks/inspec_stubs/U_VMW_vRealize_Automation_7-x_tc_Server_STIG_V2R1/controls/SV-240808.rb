control 'SV-240808' do
  title 'tc Server HORIZON accounts accessing the directory tree, the shell, or other operating system functions and utilities must be administrative accounts.'
  desc "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files.

As with all secure web server installations, tc Server files and directories must be adequately protected with correct permissions."
  desc 'check', "At the command prompt, execute the following command:

ls -alR /opt/vmware/horizon/workspace/webapps | grep -E '^-' | awk '$3 !~ /horizon|root/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following command:

chown horizon:www <file_name>

Repeat the command for each file that was returned.

Note: Replace <file_name> for the name of the file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44041r674166_chk'
  tag severity: 'high'
  tag gid: 'V-240808'
  tag rid: 'SV-240808r674168_rule'
  tag stig_id: 'VRAU-TC-000475'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-44000r674167_fix'
  tag 'documentable'
  tag legacy: ['SV-100697', 'V-90047']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
