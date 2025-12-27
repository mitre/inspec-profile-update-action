control 'SV-213509' do
  title 'JBoss must be configured to produce log records that establish which hosted application triggered the events.'
  desc 'Application server logging capability is critical for accurate forensic analysis.  Without sufficient and accurate information, a correct replay of the events cannot be determined. 

By default, no web logging is enabled in JBoss.  Logging can be configured per web application or by virtual server.  If web application logging is not set up, application activity will not be logged.

Ascertaining the correct location or process within the application server where the events occurred is important during forensic analysis.  To determine where an event occurred, the log data must contain data containing the application identity.'
  desc 'check', 'Application logs are a configurable variable.  Interview the system admin, and have them identify the applications that are running on the application server.  Have the system admin identify the log files/location where application activity is stored.

Review the log files to ensure each application is uniquely identified within the logs or each application has its own unique log file.

Generate application activity by either authenticating to the application or generating an auditable event, and ensure the application activity is recorded in the log file.  Recently time stamped application events are suitable evidence of compliance.

If the log records do not indicate which application hosted on the application server generated the event, or if no events are recorded related to application activity, this is a finding.'
  desc 'fix', 'Configure log formatter to audit application activity so individual application activity can be identified.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14732r296193_chk'
  tag severity: 'medium'
  tag gid: 'V-213509'
  tag rid: 'SV-213509r615939_rule'
  tag stig_id: 'JBOS-AS-000120'
  tag gtitle: 'SRG-APP-000097-AS-000060'
  tag fix_id: 'F-14730r296194_fix'
  tag 'documentable'
  tag legacy: ['SV-76733', 'V-62243']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
