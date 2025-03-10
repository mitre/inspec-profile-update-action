control 'SV-214311' do
  title 'The Apache web server must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time.

Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes but is not limited to time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, and flow control rules invoked.

'
  desc 'check', %q(Items to be logged are as shown in this sample line in the <'INSTALL PATH'>\conf\httpd.conf file:

LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " combined

If the web server is not configured to capture the required audit events for all sites and virtual directories, this is a finding.)
  desc 'fix', 'Configure the "LogFormat" in the "httpd.conf" file to look like the following:

LogFormat "%a %A %h %H %l %m %s %t %u %U \\"%{Referer}i\\" " combined

Restart the Apache service.

NOTE: Your log format may be using different variables based on your environment, however, it should be verified to be producing the same end result of logged elements.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15523r277436_chk'
  tag severity: 'medium'
  tag gid: 'V-214311'
  tag rid: 'SV-214311r505936_rule'
  tag stig_id: 'AS24-W1-000090'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-15521r277437_fix'
  tag satisfies: ['SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064']
  tag 'documentable'
  tag legacy: ['SV-102431', 'V-92343']
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-001487']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 f']
end
