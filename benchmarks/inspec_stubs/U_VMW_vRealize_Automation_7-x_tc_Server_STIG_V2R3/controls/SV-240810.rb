control 'SV-240810' do
  title 'tc Server VCAC accounts accessing the directory tree, the shell, or other operating system functions and utilities must be administrative accounts.'
  desc "As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files.

As with all secure web server installations, tc Server files and directories must be adequately protected with correct permissions."
  desc 'check', "At the command prompt, execute the following command:

ls -alR /etc/vcac /usr/lib/vcac/server/webapps | grep -E '^-' | awk '$3 !~ /vcac|root/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following command:

If the file was found in /etc/vcac or /usr/lib/vcac/server/webapps, execute the following command:

chown vcac:vcac <file_name>

Note: Replace <file_name> for the name of the file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44043r674172_chk'
  tag severity: 'high'
  tag gid: 'V-240810'
  tag rid: 'SV-240810r879631_rule'
  tag stig_id: 'VRAU-TC-000485'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-44002r674173_fix'
  tag 'documentable'
  tag legacy: ['SV-100701', 'V-90051']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
