control 'SV-222564' do
  title 'Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.'
  desc 'Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

If the remote connection is not closed and verified as closed, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Remote connections must be disconnected and verified as disconnected when non-local maintenance sessions have been terminated and are no longer available for use.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application maintenance functions.

If the application does not provide non-local maintenance and diagnostic capability, this requirement is not applicable.

Identify the maintenance functions/capabilities that are provided by the application, performed by an individual/admin and which can be performed remotely.

Examples include but are not limited to:

The application may provide the ability to clean up a folder of temporary files, add users, remove users, restart processes, backup certain files, manage logs, or execute diagnostic sessions.

Identify the IP address of the source system used to originate testing traffic. The IP address will be used to identify sessions on the application host so verify traffic is not traversing a proxy connection in order to reach the application host.

Access the operating system of the application host and execute the relevant OS commands to identify active TCP/IP sessions on the application host.

For example, the "netstat -a" command will provide a status of all TCP/IP connections on both Windows and UNIX systems.

Netstat output can be redirected to a file or the grep command can be used on UNIX systems to identify the specific application processes and network connections.

netstat -a |grep -i "application process name" > filename
or
netstat  -a |grep -i source IP address > filename

Utilizing the application, access using the appropriate role needed to execute maintenance tasks.

Execute a maintenance task or tasks from within the application.

Re-execute the netstat commands and identify what network connections and process IDs were created to handle the new application session.

Terminate the application session via the application interface and then execute the netstat commands a third time. The network connections should terminate or change to a state that indicates the connections are closed or are in the process of closing. Continue to execute netstat command until it is verified that the application has terminated the process sessions and closed the network connections.

Review the application logs to ensure the application has logged the disconnection event thereby verifying the disconnection.

If the application provides remote access to maintenance functions and capabilities and the remote access connections are not terminated and then verified, this is a finding.'
  desc 'fix', 'Configure the application to verify termination of remote maintenance sessions.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24234r493600_chk'
  tag severity: 'medium'
  tag gid: 'V-222564'
  tag rid: 'SV-222564r508029_rule'
  tag stig_id: 'APSC-DV-001960'
  tag gtitle: 'SRG-APP-000413'
  tag fix_id: 'F-24223r493601_fix'
  tag 'documentable'
  tag legacy: ['SV-84801', 'V-70179']
  tag cci: ['CCI-002891']
  tag nist: ['MA-4 (7)']
end
