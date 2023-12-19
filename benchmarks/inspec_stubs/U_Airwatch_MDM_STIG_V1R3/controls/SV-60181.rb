control 'SV-60181' do
  title 'The AirWatch MDM Server must centralize the review and analysis of audit records from multiple components within the server.'
  desc 'Due to the numerous functions an AirWatch MDM Server implementation processes, log files can become extremely large because of the volume of data.  The more processes that are logged, more log data is collected.  This can become very difficult to analyze manually; therefore, it is important to process them automatically and tailor the views of the data to only those events of interest based upon selectable criteria.  Without the automation of log processing, based upon events of interest to security personnel, log files will not be viewed accurately and actions will not be taken when a significant event occurs on the system because it can be too overwhelming.  Significant or meaningful events may be missed due to the sheer volume of data if logs are reviewed manually.  Reducing the auditing capability to only those events that are significant aids in supporting near real-time audit review and analysis requirements and after-the-fact investigations of security incidents.'
  desc 'check', 'Review the configuration settings to ensure the AirWatch MDM Server audit system centralizes the review and analysis of audit records from multiple components within the server. If the AirWatch MDM Server cannot support the capability to centralize the review and analysis of audit records from multiple components within the server, this is a finding.

To ensure the exporting of specific information collected by the AirWatch application to an external auditing or reporting system: click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) verify proper configuration information. (7) Check report output on external system to verify functionality.'
  desc 'fix', 'Configure the AirWatch MDM Server to centralize the review and analysis of audit records from multiple components within the server.

To export specific auditing information to external reporting system:  click the (1) "Menu" button from top tool bar, (2) click on "System Configuration" under "Configuration" heading, (3) click on "System" on left-hand tool bar, (4) click on "Enterprise Integration", (5) click on "Syslog", and (6) enter in information for applicable destination logging server in box labeled "Message Content".  (7) Click "Save".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50075r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47309'
  tag rid: 'SV-60181r1_rule'
  tag stig_id: 'ARWA-02-000038'
  tag gtitle: 'SRG-APP-111-MDM-258-SRV'
  tag fix_id: 'F-51015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
