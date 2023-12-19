control 'SV-204821' do
  title 'The application server must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'Invalid user input occurs when a user inserts data or characters into an applications data entry field and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

Application servers must ensure their management interfaces perform data input validation checks.  When invalid data is entered, the application server must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.  An example of a predictable behavior is trapping the data, logging the invalid data for forensic analysis if necessary, and continuing operation in a safe and secure manner.'
  desc 'check', 'Review the application server configuration to determine if the management interface behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.

If the application server does not meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server management interface to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4941r283104_chk'
  tag severity: 'medium'
  tag gid: 'V-204821'
  tag rid: 'SV-204821r879818_rule'
  tag stig_id: 'SRG-APP-000447-AS-000273'
  tag gtitle: 'SRG-APP-000447'
  tag fix_id: 'F-4941r283105_fix'
  tag 'documentable'
  tag legacy: ['V-57565', 'SV-71841']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
