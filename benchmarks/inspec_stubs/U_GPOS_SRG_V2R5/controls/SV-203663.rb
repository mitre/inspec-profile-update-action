control 'SV-203663' do
  title 'The operating system must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Verify the operating system generates error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3788r557234_chk'
  tag severity: 'medium'
  tag gid: 'V-203663'
  tag rid: 'SV-203663r557236_rule'
  tag stig_id: 'SRG-OS-000205-GPOS-00083'
  tag gtitle: 'SRG-OS-000205'
  tag fix_id: 'F-3788r557235_fix'
  tag 'documentable'
  tag legacy: ['V-56887', 'SV-71147']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
