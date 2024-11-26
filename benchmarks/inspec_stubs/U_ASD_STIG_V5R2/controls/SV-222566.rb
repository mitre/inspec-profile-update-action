control 'SV-222566' do
  title 'The application must terminate all sessions and network connections when non-local maintenance is completed.'
  desc 'If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Review the application documentation and interview the system administrator to determine how the application is configured to terminate network sessions after sessions have been idle for a period of time. Identify any documented exceptions.

If the application does not provide non-local maintenance and diagnostic capability, this requirement is not applicable.

For privileged management sessions the period of time is 10 minutes of inactivity.

For regular user or non-privileged sessions, the period of time is 15 minutes of inactivity.

Authenticate to the application using normal in-band access methods and as an application admin.

Perform any operation to verify access and then leave the session idle for 10 minutes and perform no activity within the application.

Access the application after the period of inactivity has expired and determine if the application still allows access.

If necessary, logout of the application, clear the browser cache, and repeat the same test procedure using the account privileges of a regular user. Leave the session inactive for 15 minutes.

If the application does not deny access after each user session has exceeded the relevant idle timeout period and there is no documented risk exceptions needed to fulfill mission requirements, this is a finding.'
  desc 'fix', 'Configure the application to expire idle user sessions after 10 minutes of inactivity for admin users and after 15 minutes of inactivity for regular users.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24236r493606_chk'
  tag severity: 'medium'
  tag gid: 'V-222566'
  tag rid: 'SV-222566r508029_rule'
  tag stig_id: 'APSC-DV-001980'
  tag gtitle: 'SRG-APP-000186'
  tag fix_id: 'F-24225r493607_fix'
  tag 'documentable'
  tag legacy: ['SV-84805', 'V-70183']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
