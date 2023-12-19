control 'SV-204722' do
  title 'The application server must produce log records containing sufficient information to establish when (date and time) the events occurred.'
  desc 'Application server logging capability is critical for accurate forensic analysis.  Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct order of the events that occurred is important during forensic analysis.  Events that appear harmless by themselves might be flagged as a potential threat when properly viewed in sequence.  By also establishing the event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered.  Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

In addition to logging event information, application servers must also log the corresponding dates and times of these events. Examples of event data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD activity, and application server-related system process activity.'
  desc 'check', 'Review the logs on the application server to determine if the date and time are included in the log event data.

If the date and time are not included, this is a finding.'
  desc 'fix', 'Configure the application server logging system to log date and time with the event.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4842r282813_chk'
  tag severity: 'medium'
  tag gid: 'V-204722'
  tag rid: 'SV-204722r508029_rule'
  tag stig_id: 'SRG-APP-000096-AS-000059'
  tag gtitle: 'SRG-APP-000096'
  tag fix_id: 'F-4842r282814_fix'
  tag 'documentable'
  tag legacy: ['V-35165', 'SV-46452']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
