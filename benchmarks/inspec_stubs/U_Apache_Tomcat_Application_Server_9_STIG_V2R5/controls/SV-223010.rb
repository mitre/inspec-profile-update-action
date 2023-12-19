control 'SV-223010' do
  title 'The application server must alert the SA and ISSO, at a minimum, in the event of a log processing failure.'
  desc 'Logs are essential to monitor the health of the system, investigate changes that occurred to the system, or investigate a security incident. When log processing fails, the events during the failure can be lost. To minimize the timeframe of the log failure, an alert needs to be sent to the SA and ISSO at a minimum.

Log processing failures include, but are not limited to, failures in the application server log capturing mechanisms or log storage capacity being reached or exceeded. In some instances, it is preferred to send alarms to individuals rather than to an entire group. Application servers must be able to trigger an alarm and send an alert to, at a minimum, the SA and ISSO in the event there is an application server log processing failure.'
  desc 'check', 'This requirement cannot be met by the Tomcat server natively and must be done at the OS. Review operating system. Ensure the OS is configured to alert the ISSO and SA in the event of an audit processing failure.

The alert notification method itself can be accomplished in a variety of ways and is not restricted to email alone. The intention is to send an alert, the method used to send the alert is not a factor of the requirement. The fix uses email but other  alert methods are acceptable.

If the OS is not configured to alert the ISSO and SA in the event of an audit processing failure, this is a finding.'
  desc 'fix', 'Procedures for meeting this requirement will vary according to the OS. For Ubuntu Linux systems, instructions for notifying via email are provided. Other alert methods are also acceptable but are not provided here.

Configure "auditd" service to notify the System Administrator (SA) and Information System Security Officer (ISSO) in the event of an audit processing failure.

Edit the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations:

action_mail_acct = root

Restart the auditd service so the changes take effect:
# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24682r426474_chk'
  tag severity: 'medium'
  tag gid: 'V-223010'
  tag rid: 'SV-223010r879570_rule'
  tag stig_id: 'TCAT-AS-001731'
  tag gtitle: 'SRG-APP-000108-AS-000067'
  tag fix_id: 'F-24671r426475_fix'
  tag 'documentable'
  tag legacy: ['SV-111571', 'V-102621']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
