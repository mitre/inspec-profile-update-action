control 'SV-222474' do
  title 'The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.'
  desc 'It is impossible to establish, correlate, and investigate the events relating to an incident if the details regarding the source of the event it not available.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where within the application the events occurred, such as which application component, application modules, filenames, and functionality.

Associating information about where the event occurred within the application provides a means of quickly investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Review application administration and/or design documents.

Identify key aspects of application architecture objects and components, e.g., Web Server, Application server, Database server.

Interview the application administrator and identify the log locations.

Access the application logs and review the log entries for events that indicate the application is auditing the internal components, objects, or functions of the application.

Confirm the event logs provide information as to which component, feature, or functionality of the application triggered the event.

Examples of the types of events to look for are as follows:

- Application and Protocol events. e.g., Application loads or unloads and Protocol use.
- Data Access events. e.g., Database connections.

Events could include reference to database library or executable initiating connectivity:

- Middleware events. e.g., Source code initiating calls or being invoked.
- Name of application modules being loaded or unloaded.
- Library loads and unloads.
- Application deployment activity.

Events written into the log must be able to be traced back to the originating component, feature or function name, service name, application name, library name etcetera in order to establish which aspect of the application triggered the event.

If the audit logs do not contain enough data in the logs to establish which component, feature or functionality of the application triggered the event, this is a finding.'
  desc 'fix', 'Configure the application to log which component, feature or functionality of the application triggered the event.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24144r493330_chk'
  tag severity: 'medium'
  tag gid: 'V-222474'
  tag rid: 'SV-222474r508029_rule'
  tag stig_id: 'APSC-DV-000990'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-24133r493331_fix'
  tag 'documentable'
  tag legacy: ['V-69431', 'SV-84053']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
