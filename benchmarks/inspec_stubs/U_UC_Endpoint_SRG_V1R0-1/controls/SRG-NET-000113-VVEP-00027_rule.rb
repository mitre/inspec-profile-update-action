control 'SRG-NET-000113-VVEP-00027_rule' do
  title 'The Unified Communications Endpoint must be configured to provide session (call detail) record generation capability.'
  desc 'Session records are commonly produced by session management and border elements. Many Unified Communications Endpoints are not capable of providing session records and instead rely on session management and border elements. Unified Communications Endpoints capable of producing session records provide supplemental confirmation of monitored events. Unified Communications Endpoints that communicate beyond these defined environments must generate session records.

Session records for Voice Video systems are generally handled in a similar fashion to audit records for other systems and are used for billing, usage analysis, and record support for actions taken. Detailed records are typically produced by the session manager but can be augmented by nontelephone endpoint records.'
  desc 'check', 'Verify the Unified Communications Endpoint provides session record generation capability. 

If the Unified Communications Endpoint does not provide session record generation capability, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to provide session record generation capability.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000113-VVEP-00027_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000113-VVEP-00027'
  tag rid: 'SRG-NET-000113-VVEP-00027_rule'
  tag stig_id: 'SRG-NET-000113-VVEP-00027'
  tag gtitle: 'SRG-NET-000113-VVEP-00027'
  tag fix_id: 'F-SRG-NET-000113-VVEP-00027_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
