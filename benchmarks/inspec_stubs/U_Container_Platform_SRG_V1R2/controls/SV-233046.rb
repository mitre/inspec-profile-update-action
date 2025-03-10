control 'SV-233046' do
  title 'All audit records must generate the event results within the container platform.'
  desc 'Within the container platform, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues, such as security incidents, that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to know the outcome of the event.'
  desc 'check', 'Review the container platform configuration to determine if audit records contain the audit event results. 

Generate audit records and review the data to validate that the record does contain the event result. 

If the container platform is not configured to generate audit records with  the event result or the audit record does not contain the event result, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records that contain the event result.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35982r601628_chk'
  tag severity: 'medium'
  tag gid: 'V-233046'
  tag rid: 'SV-233046r601629_rule'
  tag stig_id: 'SRG-APP-000099-CTR-000190'
  tag gtitle: 'SRG-APP-000099'
  tag fix_id: 'F-35950r600626_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
