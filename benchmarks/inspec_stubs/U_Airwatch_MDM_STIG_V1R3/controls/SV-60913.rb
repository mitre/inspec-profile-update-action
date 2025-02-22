control 'SV-60913' do
  title 'The AirWatch MDM Server must record an event in the audit log each time the server makes a security relevant configuration change on a managed mobile device.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. Security-relevant configuration changes, if not authorized, are a breach of system security and might indicate a broader attack is occurring. Recording security-relevant changes in the audit logs mitigates the risk that unauthorized changes will go undetected.'
  desc 'check', 'Inspect the audit logs to ensure security relevant configuration changes are being recorded. Make several security relevant configuration changes and verify these were recorded in the audit log. If any of the security relevant changes do not appear in the log, this is a finding.

To access event log: From the administration console, (1) click the "Menu" button on top of the tool bar, and (2) click "Events" under "Reports and Analytics" heading. From the "Events" menu, (3) click the "Device Events" button. (4) Filter events by clicking on the "Date Range," "Severity," "Category," or "Module" drop-down menus and define parameters, or use the search box located to the right of the drop-down filters to search the event logs.'
  desc 'fix', 'Configure the AirWatch MDM Server to record an event in the device audit log each time there is a security relevant configuration change.

To access the Device event log: From the administration console, (1) click the "Menu" button on top of the tool bar, and (2) click "Events" under "Reports and Analytics" heading. From the "Events" menu, (3) click the "Device Events" button. (4) Filter events by clicking on the "Date Range," "Severity," "Category," or "Module" drop-down menus and define parameters, or use the search box located to the right of the drop-down filters to search the event logs.'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50477r1_chk'
  tag severity: 'medium'
  tag gid: 'V-48041'
  tag rid: 'SV-60913r1_rule'
  tag stig_id: 'ARWA-02-000079'
  tag gtitle: 'SRG-APP-130-MDM-272-SRV'
  tag fix_id: 'F-51653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000347']
  tag nist: ['CM-5 (1)']
end
