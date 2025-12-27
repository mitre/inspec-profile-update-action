control 'SV-257559' do
  title 'OpenShift must configure Alert Manger Receivers to notify SA and ISSO of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

'
  desc 'check', 'Verify the AlertManager config includes a configured receiver.

1. From the Administrator perspective on the OpenShift web console, navigate to Administration >> Cluster Settings >> Configuration >> Alertmanager.

2. View the list of receivers and inspect the configuration.

3. Verify that at least one receiver is configured as either PagerDuty, Webhook, Email, or Slack according to the organizations policy.

If an alert receiver is not configured according to the organizational policy, this is a finding.'
  desc 'fix', 'Create an alert notification receiver.

1. From the Administrator perspective on the OpenShift web console, navigate to Administration >> Cluster Settings >> Configuration >> Alertmanager.

2. Select "Create Receiver".

3. Set the name and choose a Receiver Type.

4. Complete the form as per the organizations policy.

5. Click "Create".

Refer to the following documentation for more information:
https://docs.openshift.com/container-platform/4.8/monitoring/managing-alerts.html#sending-notifications-to-external-systems_managing-alerts'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61294r921618_chk'
  tag severity: 'medium'
  tag gid: 'V-257559'
  tag rid: 'SV-257559r921620_rule'
  tag stig_id: 'CNTR-OS-000690'
  tag gtitle: 'SRG-APP-000360-CTR-000815'
  tag fix_id: 'F-61218r921619_fix'
  tag satisfies: ['SRG-APP-000360-CTR-000815', 'SRG-APP-000474-CTR-001180']
  tag 'documentable'
  tag cci: ['CCI-001858', 'CCI-002702']
  tag nist: ['AU-5 (2)', 'SI-6 d']
end
