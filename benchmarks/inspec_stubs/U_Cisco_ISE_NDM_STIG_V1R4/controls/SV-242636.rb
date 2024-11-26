control 'SV-242636' do
  title 'The Cisco ISE must generate log records for a locally developed list of auditable events.'
  desc 'Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.

In Cisco ISE a logging category is a bundle of message codes that describe a function, a flow, or a use case. In Cisco ISE, each log is associated with a message code that is bundled with the logging categories according to the log message content. Logging categories help describe the content of the messages that they contain.

Logging categories promote logging configuration. Each category has a name, target, and severity level that you can set, as per your application requirement.

Cisco ISE provides predefined logging categories for services, such as Posture, Profiler, Guest, AAA (authentication, authorization, and accounting), and so on, to which you can assign log targets.'
  desc 'check', 'View the SSP syslog requirements. View the logging categories for Cisco ISE to verify the logging categories that pertain to the corresponding locally developed list of auditable events are enabled, configured, and being sent to the remote syslog target.

1. Log in to the Admin portal.
2. Choose Administration >> System >> Logging >> Logging Categories.
3. Click the radio button next to the desired logging category that pertains to the local list of auditable events and then click "Edit".
4. Choose the Log Severity Level drop-down list.
5. In the Targets field, move the secure syslog remote logging target to the Selected box.
6. Click "Save".
7. Repeat this procedure to enable all locally logging categories that pertain to the local list of auditable events.

If the Cisco ISE does not generate log records for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Enable logging categories for Cisco ISE to send auditable events to the remote syslog target.

1. Log in to the Admin portal.
2. Choose Administration >> System >> Logging >> Logging Categories.
3. Click the radio button next to the desired logging category that pertains to the local list of auditable events and then click "Edit".
4. Choose the Log Severity Level drop-down list.
5. In the Targets field, move the syslog remote logging target to the Selected box.
6. Click "Save".
7. Repeat this procedure to enable all locally logging categories that pertain to the local list of auditable events.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45911r714216_chk'
  tag severity: 'medium'
  tag gid: 'V-242636'
  tag rid: 'SV-242636r714218_rule'
  tag stig_id: 'CSCO-NM-000300'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-45868r714217_fix'
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000366']
  tag nist: ['AU-12 a', 'CM-6 b']
end
