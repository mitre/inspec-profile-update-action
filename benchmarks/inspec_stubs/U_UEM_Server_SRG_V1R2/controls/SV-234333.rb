control 'SV-234333' do
  title 'The UEM server must be configured to generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers. 

Satisfies:FAU_GEN.1.2(1) 
Reference:PP-MDM-412060'
  desc 'check', 'Verify the UEM server generates audit records containing information that establishes the identity of any individual or process associated with the event.

If the UEM server does not generate audit records containing information that establishes the identity of any individual or process associated with the event, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37518r614009_chk'
  tag severity: 'medium'
  tag gid: 'V-234333'
  tag rid: 'SV-234333r879568_rule'
  tag stig_id: 'SRG-APP-000100-UEM-000060'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-37483r614010_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
