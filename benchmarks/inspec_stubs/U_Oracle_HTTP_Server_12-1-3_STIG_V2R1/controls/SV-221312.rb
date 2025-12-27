control 'SV-221312' do
  title 'OHS must have a log level severity defined to produce sufficient log records to establish what type of events occurred.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time. 

Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogSeverity" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "NOTIFICATION:32", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogSeverity" directive at the OHS server configuration scope.

3. Set the "OraLogSeverity" directive to "NOTIFICATION:32", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23027r414619_chk'
  tag severity: 'medium'
  tag gid: 'V-221312'
  tag rid: 'SV-221312r414621_rule'
  tag stig_id: 'OH12-1X-000050'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-23016r414620_fix'
  tag 'documentable'
  tag legacy: ['SV-78681', 'V-64191']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
