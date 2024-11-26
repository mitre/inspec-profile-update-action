control 'SV-79749' do
  title 'The DataPower Gateway must off-load audit records onto a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Search Bar “Log Target” >> Log target >> Event Subscription tab. 

If “audit” is not listed under Event Category, this is a finding.

If “Rule Action” does not contain a “Filter” action, this is a finding.'
  desc 'fix', 'Search Bar “Log Target” in the Search field >> Log target >> Event Subscription tab >> Add >> Event Category “audit” >> Minimum Event Priority event priority level >> Apply >> Apply >> Save Configuration.

If the only log target is “default-log”: Type “Log Target” in the Search field >> Log target >> Main tab >> Target Type “syslog” >> syslog Facility facility >> Local Identifier identifier >> Remote Host hostname.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65887r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65259'
  tag rid: 'SV-79749r1_rule'
  tag stig_id: 'WSDP-AG-000090'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-71199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
