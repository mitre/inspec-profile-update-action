control 'SV-222471' do
  title 'The application must log user actions involving access to data.'
  desc 'When users access application data, there is risk of data compromise or seepage if the account used to access is compromised or access is granted improperly. To be able to investigate which account accessed data, the account access must be logged. Without establishing when the access event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Review and monitor the application logs. When accessing data, the logs are most likely database logs.

If the application design documents include specific data elements that require protection, ensure user access to those data elements are logged.

Utilize the application as a regular user and operate the application so as to access data elements contained within the application. This includes using the application user interface to browse through data elements, query/search data elements and using report generation capability if it exists.

Observe and determine if the application log includes an entry to indicate the user’s access to the data was recorded.

If successful access to application data elements is not recorded in the logs, this is a finding.'
  desc 'fix', 'Identify the specific data elements requiring protection and audit access to the data.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24141r493321_chk'
  tag severity: 'medium'
  tag gid: 'V-222471'
  tag rid: 'SV-222471r508029_rule'
  tag stig_id: 'APSC-DV-000960'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-24130r493322_fix'
  tag 'documentable'
  tag legacy: ['V-69425', 'SV-84047']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
