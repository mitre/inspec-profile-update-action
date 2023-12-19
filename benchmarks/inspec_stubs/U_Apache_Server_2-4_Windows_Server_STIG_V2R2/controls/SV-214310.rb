control 'SV-214310' do
  title 'The Apache web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.'
  desc 'Log records can be generated from various components within the Apache web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific Apache web server functionalities may be logged as well. The Apache web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the Apache web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.

'
  desc 'check', %q(In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If the "log_config_module" is not enabled, this is a finding.)
  desc 'fix', %q(Uncomment the "log_config_module" module line in the <'INSTALL PATH'>\conf\httpd.conf file.

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15522r277433_chk'
  tag severity: 'medium'
  tag gid: 'V-214310'
  tag rid: 'SV-214310r505936_rule'
  tag stig_id: 'AS24-W1-000070'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-15520r277434_fix'
  tag satisfies: ['SRG-APP-000089-WSR-000047', 'SRG-APP-000092-WSR-000055']
  tag 'documentable'
  tag legacy: ['SV-102427', 'V-92339']
  tag cci: ['CCI-000169', 'CCI-001464']
  tag nist: ['AU-12 a', 'AU-14 (1)']
end
