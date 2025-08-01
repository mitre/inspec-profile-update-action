control 'SV-206361' do
  title 'The web server must produce log records containing sufficient information to establish where within the web server the events occurred.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct location or process within the web server where the events occurred is important during forensic analysis. Correctly determining the web service, plug-in, or module will add information to the overall reconstruction of the logged event. For example, an event that occurred during communication to a cgi module might be handled differently than an event that occurred during a communication session to a user.

Without sufficient information establishing where the log event occurred within the web server, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine if the web server is configured to generate sufficient information to resolve in which process within the web server the log event occurred.

Request a user access the hosted application and generate logable events, and then review the logs to determine if the process of the event within the web server can be established.

If it cannot be determined where the event occurred, this is a finding.'
  desc 'fix', 'Configure the web server to generate enough information to determine in what process within the web server the log event occurred.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6622r377675_chk'
  tag severity: 'medium'
  tag gid: 'V-206361'
  tag rid: 'SV-206361r395727_rule'
  tag stig_id: 'SRG-APP-000097-WSR-000058'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-6622r377676_fix'
  tag 'documentable'
  tag legacy: ['SV-54191', 'V-41614']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
