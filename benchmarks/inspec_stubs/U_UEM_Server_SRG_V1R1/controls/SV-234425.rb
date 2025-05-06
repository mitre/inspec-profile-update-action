control 'SV-234425' do
  title 'The UEM server must reveal error messages only to the Information System Security Manager (ISSM) and Information System Security Officer (ISSO).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the application. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Satisfies:FPT_TST_EXT.1, FAU_GEN.1.2(1), FIA_UAU.1.2, FMT_SMR.1.1(1)"
  desc 'check', 'Verify the UEM server reveals error messages only to the ISSM and ISSO.

If the UEM server does not reveal error messages only to the ISSM and ISSO, this is a finding.'
  desc 'fix', 'Configure the UEM server to reveal error messages only to the ISSM and ISSO.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37610r614285_chk'
  tag severity: 'medium'
  tag gid: 'V-234425'
  tag rid: 'SV-234425r617355_rule'
  tag stig_id: 'SRG-APP-000267-UEM-000152'
  tag gtitle: 'SRG-APP-000267'
  tag fix_id: 'F-37575r614286_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
