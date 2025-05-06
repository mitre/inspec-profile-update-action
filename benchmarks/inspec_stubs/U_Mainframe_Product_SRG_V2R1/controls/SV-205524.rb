control 'SV-205524' do
  title 'The Mainframe Product must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any application providing too much information in error messages risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team. 

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Examine product documentation and code.

If error messages do not limit information provided to only that which is necessary for corrective actions, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to limit information provided to only that which is necessary for corrective actions.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5790r299805_chk'
  tag severity: 'medium'
  tag gid: 'V-205524'
  tag rid: 'SV-205524r397843_rule'
  tag stig_id: 'SRG-APP-000266-MFP-000334'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-5790r299806_fix'
  tag 'documentable'
  tag legacy: ['SV-82967', 'V-68477']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
