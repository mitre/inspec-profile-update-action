control 'SV-79805' do
  title 'The DataPower Gateway must off-load audit records onto a centralized log server in real time.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the ALG is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time which indicates that the time from event detection to off-loading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Search Bar “Log Target” >> Log target >> Event Subscription tab. 

If “audit” is not listed under Event Category, this is a finding.

If “Rule Action” does not contain a “Filter” action, this is a finding.'
  desc 'fix', 'Search Bar “Log Target” in the Search field >> Log target >> Event Subscription tab >> Add >> Event Category “audit” >> Minimum Event Priority event priority level >> Apply >> Apply >> Save Configuration.

If the only log target is “default-log”: Type “Log Target” in the Search field >> Log target >> Main tab >> Target Type “syslog” >> syslog Facility facility >> Local Identifier identifier >> Remote Host hostname.'
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65943r1_chk'
  tag severity: 'low'
  tag gid: 'V-65315'
  tag rid: 'SV-79805r1_rule'
  tag stig_id: 'WSDP-AG-000140'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-71255r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
