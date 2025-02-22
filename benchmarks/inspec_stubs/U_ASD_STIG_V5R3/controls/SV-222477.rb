control 'SV-222477' do
  title 'The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Review system documentation and discuss application operation with application administrator.

Identify application processes and application users.
Identify application components, e.g., application features framework and function. Identify server components, such as web server, database server.

Review application logs. Ensure the application event logs include an identifier or identifiers that will allow an investigator to determine the user or the application process responsible for the application event.

If the event logs do not include the appropriate identifier or identifiers, this is a finding.'
  desc 'fix', 'Configure the application to log the identity of the user and/or the process associated with the event.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24147r493339_chk'
  tag severity: 'medium'
  tag gid: 'V-222477'
  tag rid: 'SV-222477r879568_rule'
  tag stig_id: 'APSC-DV-001020'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-24136r493340_fix'
  tag 'documentable'
  tag legacy: ['V-69437', 'SV-84059']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
