control 'SV-234424' do
  title 'The UEM server must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any application providing too much information in error messages risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team. 

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers. 

Satisfies:FAU_ALT_EXT.1.1, FPT_TST_EXT.1, FAU_GEN.1.2(1), FIA_UAU.1.2, FMT_SMR.1.1(1)'
  desc 'check', 'Verify the UEM server generates error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

If the UEM server does not generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries, this is a finding.'
  desc 'fix', 'Configure the UEM server to generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37609r614282_chk'
  tag severity: 'medium'
  tag gid: 'V-234424'
  tag rid: 'SV-234424r617355_rule'
  tag stig_id: 'SRG-APP-000266-UEM-000151'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-37574r614283_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
