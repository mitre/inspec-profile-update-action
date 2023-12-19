control 'SV-205166' do
  title 'The DNS server implementation must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Review the DNS system configuration to determine if audit records exist without specific user information, when user information is available.

If audit records exist without specific user information when user information is available, this is a finding.'
  desc 'fix', 'Configure the DNS system audit settings to log specific user information whenever user information is available.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5433r392414_chk'
  tag severity: 'medium'
  tag gid: 'V-205166'
  tag rid: 'SV-205166r879568_rule'
  tag stig_id: 'SRG-APP-000100-DNS-000011'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-5433r392415_fix'
  tag 'documentable'
  tag legacy: ['SV-69039', 'V-54793']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
