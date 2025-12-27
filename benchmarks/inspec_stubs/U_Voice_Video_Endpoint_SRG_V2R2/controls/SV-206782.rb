control 'SV-206782' do
  title 'The Voice Video Endpoint processing classified calls must produce session (call detail) records containing classification level and Security Access Level (SAL).'
  desc 'Session records are commonly produced by session management and border elements. Many Voice Video Endpoints are not capable of providing session records and instead rely on session management and border elements. Voice video endpoints capable of producing session records provide supplemental confirmation of monitored events. Voice video endpoints that communicate beyond these defined environments must generate session records.

Session record content for classified calls may include additional information not pertinent to unclassified calls, such as the classification and SAL. Detailed records are typically produced by the session manager but can be augmented by non-telephone endpoint records.'
  desc 'check', 'If the Voice Video Endpoint relies exclusively on the Voice Video Session Manager for session records and does not have any capability for generating session records, this check procedure is Not Applicable.

Verify the Voice Video Endpoint produces session records containing classification level and SAL.

If the Voice Video Endpoint does not produce session records containing classification level and SAL, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to produce session records containing classification level and SAL.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7038r363869_chk'
  tag severity: 'medium'
  tag gid: 'V-206782'
  tag rid: 'SV-206782r604140_rule'
  tag stig_id: 'SRG-NET-000494-VVEP-00061'
  tag gtitle: 'SRG-NET-000494'
  tag fix_id: 'F-7038r363870_fix'
  tag 'documentable'
  tag legacy: ['V-77277', 'SV-91973']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
