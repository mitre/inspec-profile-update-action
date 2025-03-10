control 'SV-104523' do
  title 'Symantec ProxySG must configure the maintenance and health monitoring to send an alarm when a critical condition occurs for a component.'
  desc "Predictable failure prevention requires organizational planning to address device failure issues. If components key to maintaining the device's security fail to function, the device could continue operating in an insecure state. If appropriate actions are not taken when a network device failure occurs, a denial of service condition may occur which could result in mission failure since the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the network device must activate a system alert message or send an alarm.

The type of alarm should ensure that an administrator is made aware of the situation within a period specified in the site's SSP based on mission impact. Alarms may be a message send to an events server, SNMP server, email/text, or a monitored console.

The following alarms are required for ProxySG devices used in DoD.
General
* CPU utilization
* Memory utilization
* Interface(s) utilization

Licensing
* User license utilization
* Base license expiration

Status
* Disk
* Sensor Count Status
* Reboot"
  desc 'check', 'Verify the Symantec ProxySG is configured to send system health notifications.

1. Log on to Web Management Console.
2. Click Maintenance >> Health Monitoring, select the "General" tab.
3. Confirm that the Notification methods are correct for each metric (Log, Trap, and/or Email).

If the Symantec ProxySG is not configured to send system health notifications, this is a finding.'
  desc 'fix', 'Configure the Symantec ProxySG to send system health notifications.

1. Log on to the Web Management Console.
2. Click Maintenance >> Health Monitoring, select the "General" tab.
3. Click on each metric, click "Edit" and set the desired thresholds and notification types (Log, Trap, and/or Email).
4. Click "Apply".

Configure the following alarms at a minimum.
General
* CPU utilization
* Memory utilization
* Interface(s) utilization

Licensing
* User license utilization
* Base license expiration

Status
* Disk
* Sensor Count Status
* Reboot'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93883r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94693'
  tag rid: 'SV-104523r1_rule'
  tag stig_id: 'SYMP-NM-000210'
  tag gtitle: 'SRG-APP-000268-NDM-000274'
  tag fix_id: 'F-100811r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end
