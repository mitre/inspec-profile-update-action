control 'SV-95991' do
  title 'The WebSphere Application Server must be run as a non-admin user.'
  desc 'Running WebSphere as an admin user gives attackers immediate admin privileges in the event the WebSphere processes are compromised.
 
Best practice is to operate the WebSphere server with an account that has limited OS privileges.

To configure system startup: https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.multiplatform.doc/ae/trun_processrestart.html'
  desc 'check', %q(Interview systems manager.

Identify the OS user ID that the WAS server runs as.

Using relevant OS commands review OS processes and search for WAS processes (running as Java).

Ensure they are running under the assigned non-administrative user id.

For UNIX: "ps -ef|grep -i websphere"

For Windows: "wmic path win32_process where "caption = 'java.exe'" get CommandLine

If the WebSphere processes are running as the root or administrator user, this is a finding.)
  desc 'fix', 'Ensure that WAS processes are started via the specified non-privileged OS user ID when running commands such as startManager, startNode, and startServer.

If startManager and startNode are in the system startup scripts, ensure that they are not started as the root user or admin user for Windows systems. 

For example, in the UNIX system, the inittab entry may look like: "was:235:respawn:/usr/WebSphere/AppServer/bin/rc.was >/dev/console 2>&1".

Ensure the user is not a root user and is instead a regular OS user.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81277'
  tag rid: 'SV-95991r1_rule'
  tag stig_id: 'WBSP-AS-000960'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-88059r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
