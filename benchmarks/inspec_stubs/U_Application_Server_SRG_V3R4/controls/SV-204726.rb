control 'SV-204726' do
  title 'The application server must generate log records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes: time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked. 

Application servers have differing levels of logging capabilities that can be specified by setting a verbosity level. The application server must, at a minimum, be capable of establishing the identity of any user or process that is associated with any particular event.'
  desc 'check', 'Review application server documentation and the log files on the application server to determine if the logs contain information that establishes the identity of the user or process associated with log event data.

If the application server does not produce logs that establish the identity of the user or process associated with log event data, this is a finding.'
  desc 'fix', 'Configure the application server logging system to log the identity of the user or process related to the events.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4846r282825_chk'
  tag severity: 'medium'
  tag gid: 'V-204726'
  tag rid: 'SV-204726r879568_rule'
  tag stig_id: 'SRG-APP-000100-AS-000063'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-4846r282826_fix'
  tag 'documentable'
  tag legacy: ['V-35182', 'SV-46469']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
