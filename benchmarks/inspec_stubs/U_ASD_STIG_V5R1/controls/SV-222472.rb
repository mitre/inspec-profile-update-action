control 'SV-222472' do
  title 'The application must log user actions involving changes to data.'
  desc 'When users change/modify application data, there is risk of data compromise if the account used to access is compromised or access is granted improperly. To be able to investigate which account accessed data, the account making the data changes must be logged. Without establishing when the data change event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Review and monitor the application logs. When modifying data, the logs are most likely database logs.

If the application design documents include specific data elements that require protection, ensure any changes to those specific data elements are logged. Otherwise, a random check is sufficient.

If the application uses a database configured to use Transaction SQL logging this is not a finding if the application admin can demonstrate a process for reviewing the transaction log for data changes. The process must include using the transaction log and some form of query capability to identify users and the data they changed within the application and vice versa.

Utilize the application as a regular user and operate the application so as to modify a data element contained within the application.

Observe and determine if the application log includes an entry to indicate the users data change event was recorded.

If successful changes/modifications to application data elements are not recorded in the logs, this is a finding.'
  desc 'fix', 'Configure the application to log all changes to application data.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24142r493324_chk'
  tag severity: 'medium'
  tag gid: 'V-222472'
  tag rid: 'SV-222472r508029_rule'
  tag stig_id: 'APSC-DV-000970'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-24131r493325_fix'
  tag 'documentable'
  tag legacy: ['V-69427', 'SV-84049']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
