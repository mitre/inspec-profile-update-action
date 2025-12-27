control 'SV-255266' do
  title 'SSMC web server must not impede the ability to write specified log record content to an audit log server.'
  desc 'Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.'
  desc 'check', %q(Verify that the SSMC web process writes the web app and audit log files at the right location on the filesystem for log exports to work correctly:

1. Log on to SSMC appliance via SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Check the following property values in /opt/hpe/ssmc/ssmcbase/resources/log4j2.json file:

a. File name for SSMCRollingFile Appender:

$ grep "\"name\" : \"SSMCRollingFile\"" -A13 /opt/hpe/ssmc/ssmcbase/resources/log4j2.json | grep "fileName"
        "fileName" : "${logpath}/ssmc.log",
If the output does not read ' "fileName" : "${logpath}/ssmc.log", ' , this is a finding.

b. File name for LocalAuditRollingFile Appender:

$ grep "\"name\" : \"LocalAuditRollingFile\"" -A13 /opt/hpe/ssmc/ssmcbase/resources/log4j2.json | grep "fileName"
        "fileName" : "${logpath}/audit.log",
If the output does not read ' "fileName" : "${logpath}/audit.log", ' , this is a finding.)
  desc 'fix', 'Configure SSMC web process to write the web application and audit log files at the right location on the filesystem for log exports to work correctly:

1. Log on to SSMC appliance via SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Locate and update the following property values in /opt/hpe/ssmc/ssmcbase/resources/log4j2.json file:

a. File name for SSMCRollingFile Appender:

Locate the line to update with the following command: $ grep -n "\\"name\\" : \\"SSMCRollingFile\\"" -A13 /opt/hpe/ssmc/ssmcbase/resources/log4j2.json | grep "fileName"
21-        "fileName" : "${logpath}/ssmc.log",
Update: set the value for "fileName" property to "${logpath}/ssmc.log", if different, using vi editor.

b. File name for LocalAuditRollingFile Appender:

Locate the line to update with the following command: $ grep -n "\\"name\\" : \\"LocalAuditRollingFile\\"" -A13 /opt/hpe/ssmc/ssmcbase/resources/log4j2.json | grep "fileName"
51-        "fileName" : "${logpath}/audit.log",
Update: set the value for "fileName" property to "${logpath}/audit.log", if different, using vi editor.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58879r869965_chk'
  tag severity: 'medium'
  tag gid: 'V-255266'
  tag rid: 'SV-255266r879731_rule'
  tag stig_id: 'SSMC-WS-030000'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-58823r869966_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
