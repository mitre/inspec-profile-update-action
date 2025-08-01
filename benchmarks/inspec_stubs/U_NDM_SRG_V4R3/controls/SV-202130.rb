control 'SV-202130' do
  title 'The network device must generate log records for a locally developed list of auditable events'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Determine if the network device generates audit log events for a locally developed list of auditable events.

If the network device is not configured to generate audit log events for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit log events for a locally developed list of auditable events.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2256r382064_chk'
  tag severity: 'medium'
  tag gid: 'V-202130'
  tag rid: 'SV-202130r879887_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000334'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-2257r382065_fix'
  tag 'documentable'
  tag legacy: ['SV-69541', 'V-55295']
  tag cci: ['CCI-000169', 'CCI-000366']
  tag nist: ['AU-12 a', 'CM-6 b']
end
