control 'SV-206758' do
  title 'The Voice Video Endpoint must provide session (call detail) record generation capability.'
  desc 'Session records are commonly produced by session management and border elements. Many Voice Video Endpoints are not capable of providing session records and instead rely on session management and border elements. Voice video endpoints capable of producing session records provide supplemental confirmation of monitored events. Voice video endpoints that communicate beyond these defined environments must generate session records.

Session records for Voice Video systems are generally handled in a similar fashion to audit records for other systems and are used for billing, usage analysis, and record support for actions taken. Detailed records are typically produced by the session manager but can be augmented by non-telephone endpoint records.'
  desc 'check', 'If the Voice Video Endpoint relies exclusively on the Voice Video Session Manager for session records and does not have any capability for generating session records, this check procedure is Not Applicable.

Verify the Voice Video Endpoint provides session record generation capability. 

If the Voice Video Endpoint does not provide session record generation capability, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to provide session record generation capability.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7014r363797_chk'
  tag severity: 'medium'
  tag gid: 'V-206758'
  tag rid: 'SV-206758r604140_rule'
  tag stig_id: 'SRG-NET-000113-VVEP-00027'
  tag gtitle: 'SRG-NET-000113'
  tag fix_id: 'F-7014r363798_fix'
  tag 'documentable'
  tag legacy: ['SV-81227', 'V-66737']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
