control 'SV-222497' do
  title 'The applications must use internal system clocks to generate time stamps for audit records.'
  desc 'Without an internal clock used as the reference for the time stored on each event to provide a trusted common reference for the time, forensic analysis would be impeded. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose.'
  desc 'check', "Review the system documentation and interview the application administrator for details regarding application architecture and logging configuration.

Identify the application components and the logs associated with the components.

Ensure the time written into the logs coincides with the OS timeclock.

Access random audit records and review the most recent logs.
 
Access the system OS hosting the application and use the related OS commands to determine the time of the system.

Perform an action in the application that causes a log event to be written and review the log to ensure the system times and the application log times correlate; compensating for any time delays that may have occurred between running the OS time command and running the application action.

If the application doesn't use the internal system clocks to generate time stamps for the audit event logs, this is a finding."
  desc 'fix', 'Configure the application to use the hosting systems internal clock for audit record generation.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24167r493399_chk'
  tag severity: 'medium'
  tag gid: 'V-222497'
  tag rid: 'SV-222497r879575_rule'
  tag stig_id: 'APSC-DV-001250'
  tag gtitle: 'SRG-APP-000116'
  tag fix_id: 'F-24156r493400_fix'
  tag 'documentable'
  tag legacy: ['V-69477', 'SV-84099']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
