control 'SV-79665' do
  title 'The DataPower Gateway must generate audit log events for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Go to Administration >> Miscellaneous >> Manage Log Targets. Verify the settings. If they are blank, this is a finding.'
  desc 'fix', 'Go to Administration >> Miscellaneous >> Manage Log Targets. Click the log target or add one. 

Go to the Event Subscriptions tab and click on the event categories that are required to be audited.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65175'
  tag rid: 'SV-79665r1_rule'
  tag stig_id: 'WSDP-NM-000132'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-71115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
