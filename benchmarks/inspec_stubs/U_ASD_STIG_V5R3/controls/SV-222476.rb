control 'SV-222476' do
  title 'The application must produce audit records that contain information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.

Successful application events are expected to far outnumber errors.   Therefore, success events may be implied by default and not specified in the logs if this behavior is documented.'
  desc 'check', 'Review system and application documentation to identify application operation and function.

Access the application logs and review the logs to determine if the results of application operations are logged.

Successful application events are expected to far outnumber errors.   Therefore, success events may be implied by default and not specified in the logs if this behavior is documented.

The outcome will be a log record that displays the application event/operation that occurred followed by the result of the operation such as "ERROR", "FAILURE", "SUCCESS" or "PASS".

Operation outcomes may also be indicated by numeric code where a "1" might indicate success and a "0" may indicate operation failure.

If the application does not produce audit records that contain information regarding the results of application operations, this is a finding.'
  desc 'fix', 'Configure the application to include the outcome of application functions or events.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24146r493336_chk'
  tag severity: 'medium'
  tag gid: 'V-222476'
  tag rid: 'SV-222476r879567_rule'
  tag stig_id: 'APSC-DV-001010'
  tag gtitle: 'SRG-APP-000099'
  tag fix_id: 'F-24135r493337_fix'
  tag 'documentable'
  tag legacy: ['V-69435', 'SV-84057']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
