control 'SV-102583' do
  title 'The Apache web server must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time.

Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes but is not limited to time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, and flow control rules invoked.

'
  desc 'check', %q(Review the access log file. If necessary, review the <'INSTALLED PATH'>\conf\httpd.conf file to determine the location of the logs.

Items to be logged are as shown in this sample line in the <'INSTALLED PATH'>\conf\httpd.conf file:

<IfModule log_config_module>
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " combined
</IfModule>

If the web server is not configured to capture the required audit events for all sites and virtual directories, this is a finding.)
  desc 'fix', %q(Open the <'INSTALLED PATH'>\conf\httpd.conf file.

Configure the "LogFormat" to look like the following within the <IfModule log_config_module> block: 

LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " combined)
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92495'
  tag rid: 'SV-102583r1_rule'
  tag stig_id: 'AS24-W2-000090'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-98737r1_fix'
  tag satisfies: ['SRG-APP-000095-WSR-000056', 'SRG-APP-000098-WSR-000060', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000133', 'CCI-000134', 'CCI-001487']
  tag nist: ['AU-3 a', 'AU-3 d', 'AU-3 e', 'AU-3 f']
end
