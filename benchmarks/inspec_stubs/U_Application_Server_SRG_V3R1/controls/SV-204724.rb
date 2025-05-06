control 'SV-204724' do
  title 'The application server must produce log records containing sufficient information to establish the sources of the events.'
  desc 'Application server logging capability is critical for accurate forensic analysis.  Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct source, e.g., source IP, of the events is important during forensic analysis.  Correctly determining the source will add information to the overall reconstruction of the logable event.  By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if the event compromised other assets within the enterprise.

Without sufficient information establishing the source of the logged event, investigation into the cause of event is severely hindered.  Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
  desc 'check', 'Review the application server documentation and deployment configuration to determine if the application server is configured to generate sufficient information to resolve the source, e.g., source IP, of the log event.

Request a user access the application server and generate logable events, and then review the logs to determine if the source of the event can be established.

If the source of the event cannot be determined, this is a finding.'
  desc 'fix', 'Configure the application server to generate the source of each logable event.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4844r282819_chk'
  tag severity: 'medium'
  tag gid: 'V-204724'
  tag rid: 'SV-204724r508029_rule'
  tag stig_id: 'SRG-APP-000098-AS-000061'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-4844r282820_fix'
  tag 'documentable'
  tag legacy: ['V-35170', 'SV-46457']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
