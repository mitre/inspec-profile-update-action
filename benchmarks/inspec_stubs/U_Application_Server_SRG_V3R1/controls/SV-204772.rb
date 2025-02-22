control 'SV-204772' do
  title 'The application server must check the validity of all data inputs to the management interface, except those specifically identified by the organization.'
  desc 'Invalid user input occurs when a user inserts data or characters into an applications data entry field and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

Application servers must ensure their management interfaces perform data input validation checks. Input validation consists of evaluating user input and ensuring that only allowed characters are utilized. An example is ensuring that the interfaces are not susceptible to SQL injection attacks.'
  desc 'check', 'Review the application server configuration to determine if the system checks the validity of information inputs to the management interface, except those specifically identified by the organization.

If the management interface data inputs are not validated, this is a finding.'
  desc 'fix', 'Configure the application server to check the validity of data inputs into the management interface except those specifically identified by the organization.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4892r282963_chk'
  tag severity: 'medium'
  tag gid: 'V-204772'
  tag rid: 'SV-204772r508029_rule'
  tag stig_id: 'SRG-APP-000251-AS-000165'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-4892r282964_fix'
  tag 'documentable'
  tag legacy: ['SV-46723', 'V-35436']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
