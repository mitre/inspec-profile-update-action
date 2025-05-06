control 'SV-204723' do
  title 'The application server must produce log records containing sufficient information to establish where the events occurred.'
  desc 'Application server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct location or process within the application server where the events occurred is important during forensic analysis. To determine where an event occurred, the log data must contain information that identifies the source and destination of the events such as application components, modules, filenames, host names, servlets, containers, API’s, and other functionality.'
  desc 'check', 'Review the configuration settings on the application server to determine if the application server is configured to log information that establishes where within the application server the event occurred. 

The data in the log file should identify the event, the component, module, filename, host name, servlets, containers, API’s, or other functionality within the application server, as well as, any source and destination information that indicates where an event occurred.

If the application server is not configured to log where within the application server the event took place, this is a finding.'
  desc 'fix', 'Configure the application server logging system to log where the event took place.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4843r282816_chk'
  tag severity: 'medium'
  tag gid: 'V-204723'
  tag rid: 'SV-204723r508029_rule'
  tag stig_id: 'SRG-APP-000097-AS-000060'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-4843r282817_fix'
  tag 'documentable'
  tag legacy: ['SV-46454', 'V-35167']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
