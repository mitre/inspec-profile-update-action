control 'SV-79745' do
  title 'The DataPower Gateway providing user access control intermediary services must provide the capability for authorized users to select a user session to capture or view.'
  desc 'Without the capability to select a user session to capture or view, investigations into suspicious or harmful events would be hampered by the volume of information captured.

The intent of this requirement is to ensure the capability to select specific sessions to capture is available in order to support general auditing/incident investigation, or to validate suspected misuse by a specific user. Examples of session events that may be captured include, port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Search Bar “Log Target” >> Log target >> Event Subscription tab. 

If “audit” is not listed under Event Category, this is a finding. (Note: If the only Log Target available is “default-log”, this is a finding.)'
  desc 'fix', 'Search Bar “Log Target” >> Log target >> Event Subscription tab >> Add >> Event Category “audit” >> Minimum Event Priority event priority level >> Apply >> Apply >> Save Configuration.

If the only log target is “default-log”: Type “Log Target” in the Search field >> Log target >> Main tab >> Target Type “syslog” >> syslog Facility facility >> Local Identifier identifier >> Remote Host hostname.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65883r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65255'
  tag rid: 'SV-79745r1_rule'
  tag stig_id: 'WSDP-AG-000088'
  tag gtitle: 'SRG-NET-000331-ALG-000041'
  tag fix_id: 'F-71195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
