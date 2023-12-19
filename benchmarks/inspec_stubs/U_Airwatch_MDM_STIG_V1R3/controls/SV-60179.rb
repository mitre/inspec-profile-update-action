control 'SV-60179' do
  title 'The AirWatch MDM Server must utilize the integration of audit review, analysis, and reporting processes by an organizations central audit management system to support organizational processes for investigation and response to suspicious activities.'
  desc 'Auditing and logging are key components of any security architecture.  It is essential for security personnel to know what is being done, what attempted to be done, where it was done, when it was done, and by whom in order to compile an accurate collection of data for troubleshooting, forensics, etc.  Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured network element.  In order to determine what is happening within the network infrastructure or to resolve and trace an attack, it is imperative to correlate the log data from multiple network elements to acquire a clear understanding as to what happened or is happening.  Collecting log data and presenting that data in a single, consolidated view achieves this objective.'
  desc 'check', %q(Review the configuration settings to ensure the AirWatch MDM Server audit system supports the integration of audit review, analysis, and reporting processes by an organization's central audit management system to support organizational processes for investigation and response to suspicious activities. Review AirWatch MDM Server documentation and have the system administrator demonstrate the capability on the AirWatch MDM Server to transfer audit logs to a central audit system. If audit log information is not being transferred to a central audit management system, this is a finding.

To ensure the exporting of information to an external auditing or reporting system: click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) verify proper configuration information. (7) Check report output on external system to verify functionality.)
  desc 'fix', 'Configure the AirWatch MDM Server to provide audit log information to a central audit management system.

To export auditing information to external reporting system:  click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) enter in information for applicable destination logging server in box labeled "Message Content".  (7) Click "Save".'
  impact 0.3
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50073r2_chk'
  tag severity: 'low'
  tag gid: 'V-47307'
  tag rid: 'SV-60179r1_rule'
  tag stig_id: 'ARWA-03-000037'
  tag gtitle: 'SRG-APP-110-MDM-257-SRV'
  tag fix_id: 'F-51013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000152']
  tag nist: ['AU-6 (1)']
end
