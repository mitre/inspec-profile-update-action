control 'SV-79573' do
  title 'The DataPower Gateway must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.'
  desc 'check', 'Type “Log Target” in the Search field >> Log target >> Event Subscription tab. 

If “audit” in not listed under Event Category, this is a finding. 

If “Rule Action” does not contain a “Filter” action, this is a finding.'
  desc 'fix', 'Type “Log Target” in the Search field >> Log target >> Event Subscription tab >> Add >> Event Category “audit” >> Minimum Event Priority event priority level >> Apply >> Apply >> Save Configuration.

If the only log target is “default-log”: Type “Log Target” in the Search field >> Log target >> Main tab >> Target Type “syslog” >> syslog Facility facility >> Local Identifier identifier >> Remote Host hostname.'
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65709r1_chk'
  tag severity: 'low'
  tag gid: 'V-65083'
  tag rid: 'SV-79573r1_rule'
  tag stig_id: 'WSDP-NM-000042'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-71023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
