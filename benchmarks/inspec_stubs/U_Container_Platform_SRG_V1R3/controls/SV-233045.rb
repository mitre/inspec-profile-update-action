control 'SV-233045' do
  title 'All audit records must identify the source of the event within the container platform.'
  desc 'Audit data is important when there are issues, to include security incidents that must be investigated. Since the audit data may be part of a larger audit system, it is important for the audit data to also include the container platform name for traceability back to the container platform itself and not just the container platform components.'
  desc 'check', 'Review container platform audit policy configuration for logons establishing the sources of events. 

Ensure audit policy is configured to generate sufficient information to resolve the source, e.g., source IP, of the log event. 

Verify records showing by requesting a user access the container platform and generate log events, and then review the logs to determine if the source of the event can be established. 

If the source of the event cannot be determined, this is a finding.'
  desc 'fix', 'Configure the container platform registry, keystore, and runtime to generate the source of each loggable event. Revise all applicable system documentation.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35981r601626_chk'
  tag severity: 'medium'
  tag gid: 'V-233045'
  tag rid: 'SV-233045r601627_rule'
  tag stig_id: 'SRG-APP-000098-CTR-000185'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-35949r600623_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
