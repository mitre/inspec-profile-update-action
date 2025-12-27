control 'SV-54189' do
  title 'The web server must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time. 

Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if the web server contains sufficient information to establish what type of event occurred.

Request a user access the hosted applications, and verify sufficient information is recorded.

If sufficient information is not logged, this is a finding.'
  desc 'fix', 'Configure the web server to record sufficient information to establish what type of events occurred.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48041r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41612'
  tag rid: 'SV-54189r3_rule'
  tag stig_id: 'SRG-APP-000095-WSR-000056'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-47071r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
