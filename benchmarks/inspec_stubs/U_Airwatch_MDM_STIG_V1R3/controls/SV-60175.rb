control 'SV-60175' do
  title 'The AirWatch MDM Server must support the transfer of audit logs to remote log or management servers.'
  desc 'AirWatch MDM Server auditing capability is critical for accurate forensic analysis. The ability to transfer audit logs often is necessary to quickly isolate them, protect their integrity, and analyze their contents. An important aspect of security is maintaining awareness of what users have tried to do with their devices and what activities and actions MDM administrators have made.'
  desc 'check', 'Ensure the audit logs can be transferred from the AirWatch MDM Server to a storage location other than the AirWatch MDM Server itself. The systems administrator of the device may demonstrate this capability using an audit management application or other means. Audit records will be logged on the device for various actions, especially those related to sensitive or potentially suspicious activities. The specific events to log and the information recorded for each will be a function of policy. If audit logs cannot be transferred on request or on a periodic schedule, this is a finding.

To ensure the exporting of information to an external auditing or reporting system: click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and verify proper configuration information. (6) Check report output on external system to verify functionality.'
  desc 'fix', 'Configure the AirWatch MDM Server to support the transfer of audit logs to remote log or management servers.

To export auditing information to external reporting system:  click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) enter in information for applicable destination logging server.  (7) Click "Save" and then (8) click "Test Connection" button to verify connection to external auditing server.'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50069r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47303'
  tag rid: 'SV-60175r1_rule'
  tag stig_id: 'ARWA-01-000027'
  tag gtitle: 'SRG-APP-102-MDM-247-SRV'
  tag fix_id: 'F-51009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
