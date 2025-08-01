control 'SV-204717' do
  title 'The application server must generate log records for access and authentication events.'
  desc 'Log records can be generated from various components within the application server.  From an application server perspective, certain specific application server functionalities may be logged as well.  The application server must allow the definition of what events are to be logged.  As conditions change, the number and types of events to be logged may change, and the application server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events.'
  desc 'check', 'Review the application server documentation and the deployed system configuration to determine if, at a minimum, system startup and shutdown, system access, and system authentication events are logged.

If the logs do not include the minimum logable events, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records for system startup and shutdown, system access, and system authentication events.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4837r282798_chk'
  tag severity: 'medium'
  tag gid: 'V-204717'
  tag rid: 'SV-204717r508029_rule'
  tag stig_id: 'SRG-APP-000089-AS-000050'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-4837r282799_fix'
  tag 'documentable'
  tag legacy: ['SV-46428', 'V-35141']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
