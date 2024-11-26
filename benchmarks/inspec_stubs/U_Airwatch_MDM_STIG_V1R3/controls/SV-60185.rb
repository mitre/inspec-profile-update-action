control 'SV-60185' do
  title 'The AirWatch MDM Server must automatically process audit records for events of interest based upon selectable, event criteria.'
  desc 'Due to the numerous functions an AirWatch MDM Server implementation processes, log files can become extremely large because of the volume of data.  The more processes that are logged, the more log data is collected.  This can become very difficult to analyze manually; therefore, it is important to process them automatically and tailor the views of the data to only those events of interest based upon selectable criteria.  Without the automation of log processing, based upon events of interest to security personnel, log files will not be viewed accurately and actions will not be taken when a significant event occurs on the system because it can be too overwhelming.  Significant or meaningful events may be missed due to the sheer volume of data if logs are reviewed manually.'
  desc 'check', 'Review the configuration settings to ensure the AirWatch MDM Server audit feature automatically processes audit records for events of interest based upon selectable, event criteria. Review AirWatch MDM Server documentation and audit configuration. If the AirWatch MDM Server does not automatically process audit records for events of interest based upon selectable, event criteria, this is a finding.

To verify this information is being recorded in the AirWatch system, access the Events page: from the administration console, click the (1) "Menu" button on top tool bar, and (2) click "Events" under "Reports and Analytics" heading. (3) From the "Events" menu, choose "Device Events" or "Console Events" as applicable, and (4) verify Events are being recorded by the AirWatch system.

To verify the exporting of specific information collected by the AirWatch application to an external auditing or reporting system: click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) verify proper configuration information. (7) Check report output on external system to verify functionality.'
  desc 'fix', 'Configure the AirWatch MDM Server to automatically process audit records for events of interest based upon selectable, event criteria audit records to be used by a report generation capability.

To access an event log:  (1) from the administration console, click the "Menu" button on top tool bar, and (2) click "Events" under "Reports and Analytics" heading.  From the "Events" menu, (3) click the "Device Events" or "Console Events" button.  (4) Filter events by clicking on the "Date Range," "Severity," "Category," or "Module" drop-down menus and define parameters, or use the search box located to the right of the drop-down filters to search the event logs.

To export specific auditing information to external reporting system:  click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) enter in information for applicable destination logging server in box labeled "Message Content".  (7) Click "Save".'
  impact 0.3
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50079r2_chk'
  tag severity: 'low'
  tag gid: 'V-47313'
  tag rid: 'SV-60185r1_rule'
  tag stig_id: 'ARWA-03-000041'
  tag gtitle: 'SRG-APP-115-MDM-261-SRV'
  tag fix_id: 'F-51019r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
