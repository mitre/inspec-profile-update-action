control 'SV-254105' do
  title 'Nutanix AOS must be configured to send Cluster Check alerts to the SA and ISSO.'
  desc 'Logs are essential to monitor the health of the system, investigate changes that occurred to the system, or investigate a security incident. When log processing fails, the events during the failure can be lost. To minimize the timeframe of the log failure, an alert needs to be sent to the SA and ISSO at a minimum.

Log processing failures include, but are not limited to, failures in the application server log capturing mechanisms or log storage capacity being reached or exceeded. In some instances, it is preferred to send alarms to individuals rather than to an entire group. Application servers must be able to trigger an alarm and send an alert to, at a minimum, the SA and ISSO in the event there is an application server log processing failure.'
  desc 'check', 'Confirm Nutanix AOS is set to send SMTP alerts to the organization identified email address(es).

1. Log in to Nutanix Prism Elements.
2. Select "Health" dashboard.
3. On the Actions tab, select "Set NCC Frequency".

If the Frequency setting and email address(es) are not set to organization-identified frequency and recipient, this is a finding.'
  desc 'fix', 'Configure Nutanix Cluster Check (NCC) within Prism Elements to meet the Organization identified frequency and recipient.

1. Log in to Nutanix Prism Elements.
2. Select "Health" dashboard.
3. On the Actions tab, select "Set NCC Frequency".
4. Enter frequency timeframe.
5. Enter recipient email address(es).'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57590r846401_chk'
  tag severity: 'medium'
  tag gid: 'V-254105'
  tag rid: 'SV-254105r846403_rule'
  tag stig_id: 'NUTX-AP-000150'
  tag gtitle: 'SRG-APP-000108-AS-000067'
  tag fix_id: 'F-57541r846402_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
