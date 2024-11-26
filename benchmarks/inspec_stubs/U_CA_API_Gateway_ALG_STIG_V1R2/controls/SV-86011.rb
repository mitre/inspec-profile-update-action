control 'SV-86011' do
  title 'The CA API Gateway must generate error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Providing too much information in error messages risks compromising the data and security of the application and system.

Organizations must carefully consider the structure/content of error messages. The required information within error messages will vary based on the protocol and error condition. Information that could be exploited by adversaries includes, for example, ICMP messages that reveal the use of firewalls or access-control lists.

The CA API Gateway must include within the Registered Services Policies customized error responses revealing only the necessary information as required by the organization.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services that require a customized error response, revealing only the necessary information about an error. 

Verify the "Customize Error Response" Assertion is included in the policy and placed in accordance with organizational requirements. 

If it is not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click each of the Registered Services that require a customized error response and did not include a "Customize Error Response" Assertion.

Add the "Customize Error Response" Assertion to the policy, placing and configuring it in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71387'
  tag rid: 'SV-86011r1_rule'
  tag stig_id: 'CAGW-GW-000490'
  tag gtitle: 'SRG-NET-000273-ALG-000129'
  tag fix_id: 'F-77705r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
