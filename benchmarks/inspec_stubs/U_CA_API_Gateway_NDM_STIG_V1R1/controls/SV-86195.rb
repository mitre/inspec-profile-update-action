control 'SV-86195' do
  title 'The CA API Gateway must generate audit log events for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Examine "/etc/audit/audit.rules" to confirm any custom developed rules are contained within the file.

If the "/etc/audit/audit.rules" does not contain the custom developed rules within the file, this is a finding.'
  desc 'fix', 'The Gateway relies on the standard Linux audit subsystem. The subsystem is configurable by modifying /etc/audit/audit.rules. Custom rules can be added to this file. 

See the Linux man-page for audit.rules(7) for detail about specifying custom rules.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71571'
  tag rid: 'SV-86195r1_rule'
  tag stig_id: 'CAGW-DM-000360'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-77895r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
