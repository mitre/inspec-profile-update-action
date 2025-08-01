control 'SV-222561' do
  title 'Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.'
  desc 'Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

If events associated with non-local administrative access or diagnostic sessions are not logged and audited, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application maintenance functions.

If the application does not provide non-local maintenance and diagnostic capability, this requirement is not applicable.

Identify the maintenance functions/capabilities that are provided by the application and performed by an individual which can be performed remotely.

For example, the application may provide the ability to clean up a folder of temporary files, add users, remove users, restart processes, backup certain files, manage logs, or execute diagnostic sessions.

Identify and open the audit logs that capture maintenance actions performed by the application.

Accessing the application in the appropriate role to execute maintenance tasks, perform several maintenance tasks and observe the logs.

If the application provides maintenance functions and capabilities and those functions are not logged when they are executed, this is a finding.'
  desc 'fix', 'Configure the application to log when application maintenance functionality is executed remotely.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24231r493591_chk'
  tag severity: 'medium'
  tag gid: 'V-222561'
  tag rid: 'SV-222561r879782_rule'
  tag stig_id: 'APSC-DV-001930'
  tag gtitle: 'SRG-APP-000409'
  tag fix_id: 'F-24220r493592_fix'
  tag 'documentable'
  tag legacy: ['SV-84793', 'V-70171']
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
