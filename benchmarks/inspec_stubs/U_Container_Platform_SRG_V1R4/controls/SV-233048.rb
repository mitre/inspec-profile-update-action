control 'SV-233048' do
  title 'All audit records must identify any containers associated with the event within the container platform.'
  desc 'Without information that establishes the identity of the containers offering user services or running on behalf of a user within the platform associated with audit events, security personnel cannot determine responsibility for potentially harmful events.'
  desc 'check', 'Review the container platform configuration to determine if it is configured to generate audit records that contain the component information that generated the audit record. 

Generate audit records and review the data to determine if records are generated containing the component information that generated the record. 

If the container platform is not configured to generate audit records containing the component information or records are generated that do not contain the component information that generated the record, this is a finding.'
  desc 'fix', 'Configure the container platform to include the component information that generated the audit record.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35984r601632_chk'
  tag severity: 'medium'
  tag gid: 'V-233048'
  tag rid: 'SV-233048r879568_rule'
  tag stig_id: 'SRG-APP-000100-CTR-000200'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-35952r600632_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
