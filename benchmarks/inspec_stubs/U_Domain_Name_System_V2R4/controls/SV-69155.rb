control 'SV-69155' do
  title 'The DNS implementation must generate audit records for the success and failure of start and stop of the name server service or daemon.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being performed on the system, where an event occurred, when an event occurred, and by whom the event was triggered, in order to compile an accurate risk assessment. Logging the actions of specific events provides a means to investigate an attack, to recognize resource utilization or capacity thresholds, or to simply identify an improperly configured DNS system. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Review the DNS system to determine if it is configured to log success and failure of the start and stop of the name server service or daemon. If the DNS system is not configured to log these events, this is a finding.'
  desc 'fix', 'Configure the DNS system to log success and failure of the start and stop of the name service or daemon.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55535r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54909'
  tag rid: 'SV-69155r1_rule'
  tag stig_id: 'SRG-APP-000504-DNS-000074'
  tag gtitle: 'SRG-APP-000504-DNS-000074'
  tag fix_id: 'F-59771r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
