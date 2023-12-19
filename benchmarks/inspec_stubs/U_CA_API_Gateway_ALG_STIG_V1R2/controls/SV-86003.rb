control 'SV-86003' do
  title 'The CA API Gateway providing content filtering must block malicious code upon detection.'
  desc 'Taking an appropriate action based on local organizational incident handling procedures minimizes the impact of malicious code on the network.

The CA API Gateway must be configured to integrate with an ICAP enabled Intrusion Detection System such as McAfee, Sophos, or Symantec. These systems must be configured in accordance with organizational requirements, which must include the blocking of malicious code once detected.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require the blocking of malicious code once detected. 

Verify the "Scan Using ICAP-Enabled Antivirus" Assertion is included in the policy. If it is not, check to see if it has been added to a Global Policy. 

If the Assertion is not present in either Global or Registered Services policy, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that did not have the "Scan Using ICAP-Enabled Antivirus" Assertion.

Add the "Scan Using ICAP-Enabled Antivirus" Assertion, configure the parameters for the Assertion in accordance with organizational requirements, and click the "Save and Activate" button. 

If the organization requires that all Registered Services require the ability to block malicious code upon detection, consider adding the "Scan Using ICAP-Enabled Antivirus" Assertion to a Global Policy to meet this requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71379'
  tag rid: 'SV-86003r1_rule'
  tag stig_id: 'CAGW-GW-000450'
  tag gtitle: 'SRG-NET-000249-ALG-000134'
  tag fix_id: 'F-77697r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
