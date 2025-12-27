control 'SV-204725' do
  title 'The application server must produce log records that contain sufficient information to establish the outcome of events.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

Success and failure indicators ascertain the outcome of a particular application server event or function. As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.  Event outcome may also include event-specific results (e.g., the security state of the information system after the event occurred).'
  desc 'check', 'Review application server documentation and the log files on the application server to determine if the logs contain information that establishes the outcome of event data.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server logging system to log the event outcome.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4845r282822_chk'
  tag severity: 'medium'
  tag gid: 'V-204725'
  tag rid: 'SV-204725r879567_rule'
  tag stig_id: 'SRG-APP-000099-AS-000062'
  tag gtitle: 'SRG-APP-000099'
  tag fix_id: 'F-4845r282823_fix'
  tag 'documentable'
  tag legacy: ['V-35176', 'SV-46463']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
