control 'SV-82741' do
  title 'The Mainframe Product must generate audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Examine installation and configuration settings.

Verify data written to external security manager audit files and/or SMF records contain information that details the identity of individuals or processes associated with the event. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit records written to external security manager audit files and/or SMF records to contain information to establish the identity of any individual or process associated with the event.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68251'
  tag rid: 'SV-82741r1_rule'
  tag stig_id: 'SRG-APP-000100-MFP-000145'
  tag gtitle: 'SRG-APP-000100-MFP-000145'
  tag fix_id: 'F-74365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
