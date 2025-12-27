control 'SV-204728' do
  title 'The application server must alert the SA and ISSO, at a minimum, in the event of a log processing failure.'
  desc 'Logs are essential to monitor the health of the system, investigate changes that occurred to the system, or investigate a security incident.  When log processing fails, the events during the failure can be lost.  To minimize the timeframe of the log failure, an alert needs to be sent to the SA and ISSO at a minimum.

Log processing failures include, but are not limited to, failures in the application server log capturing mechanisms or log storage capacity being reached or exceeded. In some instances, it is preferred to send alarms to individuals rather than to an entire group. Application servers must be able to trigger an alarm and send an alert to, at a minimum, the SA and ISSO in the event there is an application server log processing failure.'
  desc 'check', 'Review application server log configuration.  Verify the application server sends alerts to the SA and ISSO in the event of a log processing failure.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server log feature to alert the SA and ISSO in the event of a log processing failure.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4848r282831_chk'
  tag severity: 'medium'
  tag gid: 'V-204728'
  tag rid: 'SV-204728r508029_rule'
  tag stig_id: 'SRG-APP-000108-AS-000067'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-4848r282832_fix'
  tag 'documentable'
  tag legacy: ['V-35186', 'SV-46473']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
