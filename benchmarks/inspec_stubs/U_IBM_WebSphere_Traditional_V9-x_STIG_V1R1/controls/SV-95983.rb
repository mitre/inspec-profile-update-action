control 'SV-95983' do
  title 'The WebSphere Application Server process must not be started from the command line with the -password option.'
  desc 'The use of the -password option to launch a WebSphere process from the command line can result in a security exposure. Password information may become visible to any user with the ability to view system processes. For example, on a Linux system the "ps" command will display all running processes, which would include all of the command line flags used to start a WebSphere process.'
  desc 'check', %q(Review System Security Plan documentation.

Interview the system administrator.

Access operating system to list commands currently running.

For UNIX: run "ps -ef | grep -i wsadmin.sh"

For windows: from a DOS prompt as admin user run "WMIC path win32_process where "caption='wsadmin.exe'" get CommandLine"

If the results show "wsadmin.sh(exe) -user <username> -password <password>", this is a finding.)
  desc 'fix', 'When starting WebSphere commands, such as wsadmin, stopManager, stopNode, stopServer, or syncNode; do not use the "-password <password>" option.

Use the interactive mode instead; you will be prompted for user id and password.

For scripts, you may configure user id and password in the "connector properties" files. These files are under "Profile_Root/Properties" folder.

- soap.client.props: for default SOAP
- sas.client.props : for RMI and JSR160RMI connectors
- ipc.client.props: for IPC connector'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80967r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81269'
  tag rid: 'SV-95983r1_rule'
  tag stig_id: 'WBSP-AS-000910'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-88049r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
