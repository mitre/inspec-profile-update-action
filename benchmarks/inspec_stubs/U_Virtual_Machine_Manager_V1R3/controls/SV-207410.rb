control 'SV-207410' do
  title 'The VMM must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any VMM providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which VMMs are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Verify the VMM generates error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7667r365640_chk'
  tag severity: 'medium'
  tag gid: 'V-207410'
  tag rid: 'SV-207410r379105_rule'
  tag stig_id: 'SRG-OS-000205-VMM-000760'
  tag gtitle: 'SRG-OS-000205'
  tag fix_id: 'F-7667r365641_fix'
  tag 'documentable'
  tag legacy: ['V-57021', 'SV-71281']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
