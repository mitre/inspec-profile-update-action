control 'SV-54177' do
  title 'The web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.'
  desc 'check', 'Review the web server documentation and the deployed system configuration to determine if, at a minimum, system startup and shutdown, system access, and system authentication events are logged.

If the logs do not include the minimum logable events, this is a finding.'
  desc 'fix', 'Configure the web server to generate log records for system startup and shutdown, system access, and system authentication events.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48029r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41600'
  tag rid: 'SV-54177r3_rule'
  tag stig_id: 'SRG-APP-000089-WSR-000047'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-47059r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
