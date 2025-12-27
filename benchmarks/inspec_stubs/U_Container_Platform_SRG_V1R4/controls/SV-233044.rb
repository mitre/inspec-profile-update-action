control 'SV-233044' do
  title 'All audit records must identify where in the container platform the event occurred.'
  desc 'Within the container platform, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues, such as security incidents, that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to know where within the container platform the event occurred.'
  desc 'check', 'Review the container platform configuration to determine if all audit records identify where in the container platform the event occurred. 

Generate audit records and view the audit records to verify that the records do identify where in the container platform the event occurred. 

If the container platform is not configured to generate audit records that identify where in the container platform the event occurred, or if the generated audit records do not identify where in the container platform the event occurred, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records that identify where in the container platform the event occurred.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35980r601624_chk'
  tag severity: 'medium'
  tag gid: 'V-233044'
  tag rid: 'SV-233044r879565_rule'
  tag stig_id: 'SRG-APP-000097-CTR-000180'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-35948r600620_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
