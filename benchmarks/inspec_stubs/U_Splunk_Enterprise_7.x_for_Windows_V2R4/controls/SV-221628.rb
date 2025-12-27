control 'SV-221628' do
  title 'Splunk Enterprise must be configured to notify the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.'
  desc 'Detecting when multiple systems are showing anomalies can often indicate an attack. Notifying appropriate personnel can initiate a proper response and mitigation of the attack.

Splunk can aggregate events from multiple devices and create alerts when specific events occur. Detecting similar events on multiple devices simultaneously may indicate an attack. The ability to alert and report on this activity can aid in thwarting an attack.'
  desc 'check', 'Interview the SA to verify that a process exists to notify the SA and ISSO, at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.

Interview the ISSO to confirm receipt of this notification.

If a report does not exist, or the ISSO does not confirm receipt of this report, this is a finding.'
  desc 'fix', 'Configure Splunk Enterprise, using the reporting and notification tools, to notify the SA and ISSO, at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23343r416341_chk'
  tag severity: 'medium'
  tag gid: 'V-221628'
  tag rid: 'SV-221628r879887_rule'
  tag stig_id: 'SPLK-CL-000320'
  tag gtitle: 'SRG-APP-000516-AU-000350'
  tag fix_id: 'F-23332r416342_fix'
  tag 'documentable'
  tag legacy: ['SV-111347', 'V-102403']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
