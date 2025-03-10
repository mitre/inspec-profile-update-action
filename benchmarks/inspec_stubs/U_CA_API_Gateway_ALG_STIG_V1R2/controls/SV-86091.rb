control 'SV-86091' do
  title 'The CA API Gateway must reveal error messages only to the ISSO, ISSM, and SCA.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can give configuration details about the network element.

Limiting access to system logs and administrative consoles to authorized personnel will help to mitigate this risk. However, user feedback and error messages should also be restricted by type and content in accordance with security best practices (e.g., ICMP messages).

The CA API Gateway must be configured within the policies of a Registered Service to only pass limited error messaging to the end user of a Registered Service. Additional error messages will be recorded in audit logs, and the audit logs are controlled via role-based access."
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring limited error messaging feedback to end users. 

Verify that the policy is configured to deliver limited error feedback to the user via the "Customize Error Response" and/or "Customize Soap Fault Response" Assertion in accordance with organizational requirements. 

If it is not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring limited error messaging feedback to end users that were not configured properly. 

Add the "Customize Error Response" and/or "Customize Soap Fault Response" Assertion and configure in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71467'
  tag rid: 'SV-86091r1_rule'
  tag stig_id: 'CAGW-GW-000850'
  tag gtitle: 'SRG-NET-000402-ALG-000130'
  tag fix_id: 'F-77787r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
