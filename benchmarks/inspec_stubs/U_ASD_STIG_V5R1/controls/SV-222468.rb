control 'SV-222468' do
  title 'The application must initiate session auditing upon startup.'
  desc 'If the application does not begin logging upon startup, important log events could be missed.'
  desc 'check', 'Examine the application design documentation and interview the application administrator to identify application logging behavior.

If the application is writing to an existing log or log file:

Open and monitor the application log.

Start the application service and view the log entries. 

Log entries indicating the application is starting should commence as soon as the application starts. Determine if the log events correlate with the time the application was started and if event log entries include an application start up sequence of events.

If the application writes events to a new log on startup: 

Identify location logs are written to, start the application and then identify and access the new log.

Determine if the log events correlate with the time the application was started and if event log entries include an application start up sequence of events.

If the application does not begin logging events upon start up, this is a finding.'
  desc 'fix', 'Configure the application to begin logging application events as soon as the application starts up.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24138r493312_chk'
  tag severity: 'medium'
  tag gid: 'V-222468'
  tag rid: 'SV-222468r508029_rule'
  tag stig_id: 'APSC-DV-000910'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-24127r493313_fix'
  tag 'documentable'
  tag legacy: ['SV-84041', 'V-69419']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
