control 'SV-99933' do
  title 'Lighttpd must prohibit non-privileged accounts from accessing the directory tree, the shell, or other operating system functions and utilities.'
  desc "As a rule, accounts on the Lighttpd server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the Lighttpd server. The resources to which these accounts have access must also be closely monitored and controlled. Only the system administrator needs access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and the Lighttpd server configuration files."
  desc 'check', %q(At the command prompt, execute the following command:

stat -c "%a %g %G %n" `find /opt/vmware/share/htdocs /opt/vmware/etc/lighttpd /opt/vmware/share/lighttpd -type f` | awk '$1 !~ /^..0/ || $3 !~ /root/ {print}'

If any files are returned, this is a finding.)
  desc 'fix', 'At the command prompt, execute the following commands:

Note: Replace <file_name> for the name of the file that was returned.

chown root:root <file_name>

chmod 640 <file_name>

Repeat the commands for each file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88975r1_chk'
  tag severity: 'high'
  tag gid: 'V-89283'
  tag rid: 'SV-99933r1_rule'
  tag stig_id: 'VRAU-LI-000255'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-96025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
