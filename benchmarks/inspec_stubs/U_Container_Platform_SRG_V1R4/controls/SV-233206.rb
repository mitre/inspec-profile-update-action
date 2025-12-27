control 'SV-233206' do
  title "The container platform must audit non-local maintenance and diagnostic sessions' organization-defined audit events associated with non-local maintenance."
  desc 'To fully investigate an attack, it is important to understand the event and those events taking place during the same time period. Often, non-local administrative access and diagnostic sessions are not logged. These events are seen as only administrative functions and not worthy of being audited, but these events are important in any investigation and are a major tool for assessing and investigating attacks.'
  desc 'check', "Review the container platform to verify if the platform is auditing non-local maintenance and diagnostic sessions' organization-defined audit events. 

If the container platform is not auditing non-local maintenance and diagnostic sessions' organization-defined audit events, this is a finding."
  desc 'fix', "Configure the container platform to audit non-local maintenance and diagnostic sessions' organization-defined audit events."
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36142r601807_chk'
  tag severity: 'medium'
  tag gid: 'V-233206'
  tag rid: 'SV-233206r879782_rule'
  tag stig_id: 'SRG-APP-000409-CTR-000990'
  tag gtitle: 'SRG-APP-000409'
  tag fix_id: 'F-36110r601106_fix'
  tag 'documentable'
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
