control 'SV-222568' do
  title 'The application must terminate all network connections associated with a communications session at the end of the session.'
  desc 'Networked applications routinely open connections to and from other systems as part of their design and function.  When connections are opened by the application, system resources are consumed.  Terminating the network connection at the end of the application session frees up these resources for later use and aids in maintaining system stability. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. 

This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

Many applications rely on the underlying OS to control the network connection aspect of the application which is perfectly acceptable.

Additionally, application specific operational issues may occasionally be encountered which dictate exceptions be granted to this requirement in order to ensure continuity of operations and application availability.

When the aforementioned type of situation occurs, the root cause of the issue as well as the mitigations implemented in order to prevent a loss of availability must be documented.   Common mitigation procedures include but are not limited to stopping and restarting application or system services in order to manually release system resources.'
  desc 'check', %q(Review the application documentation and interview the system administrator to determine how the application is designed and configured to terminate network connections at the end of the application session.

Identify any documented exceptions to the requirement and review associated mitigations.

If the application provides a management interface for controlling or monitoring application network sessions, access that management interface.  Monitor application network activity.  

If the application utilizes the underlying OS to control network connections, access the command prompt of the OS.  Run the OS command for observing network connections at the OS.  For Windows and Unix OS's, use the "netstat" command.  Include command parameters that identify the application and/or process ID. netstat /? or -h provides the list of available parameters.

Observe network activity and associate application processes with network connections.  Repeat use of the command to identify changing network state.

Determine if application session network connections are being terminated at the end of the session by observing the "state" column of the netstat command output with each iteration.

If the application does not terminate network connections when application sessions end, this is a finding.

If exceptions are documented with no mitigation this is a finding.)
  desc 'fix', 'Configure or design the application to terminate application network sessions at the end of the session.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24238r493612_chk'
  tag severity: 'medium'
  tag gid: 'V-222568'
  tag rid: 'SV-222568r508029_rule'
  tag stig_id: 'APSC-DV-002000'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-24227r493613_fix'
  tag 'documentable'
  tag legacy: ['SV-84809', 'V-70187']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
