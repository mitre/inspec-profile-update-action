control 'SV-86009' do
  title 'The CA API Gateway providing content filtering must automatically update malicious code protection mechanisms.'
  desc 'The malicious software detection functionality on network elements needs to be constantly updated in order to identify new threats as they are discovered.

All malicious software detection functions must come with an update mechanism that automatically updates the application and any associated signature definitions. The organization (including any contractor to the organization) is required to promptly install security-relevant malicious code protection updates. Examples of relevant updates include antivirus signatures, detection heuristic rule sets, and/or file reputation data employed to identify and/or block malicious software from executing.

Malicious code includes viruses, worms, trojan horses, and spyware.

The CA API Gateway must be configured to integrate with an ICA- enabled Intrusion Detection System such as McAfee, Sophos, or Symantec. These systems must then be configured to update their protection mechanisms and signature definitions in accordance with organizational requirements. The CA API Gateway does not offer this feature beyond the integration with the third-party systems.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require updating of malicious code mechanisms.

Verify the "Scan Using ICAP-Enabled Antivirus" Assertion is included in the policy. If it is not, check to see if it has been added to a Global Policy. 

If the Assertion is not present in either Global or Registered Services policy, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that did not have the "Scan Using ICAP-Enabled Antivirus" Assertion.

Add the "Scan Using ICAP-Enabled Antivirus" Assertion, configure the parameters for the Assertion in accordance with organizational requirements, and click the "Save and Activate" button. 

If the organization requires that all Registered Services require this ability, consider adding the "Scan Using ICAP-Enabled Antivirus" Assertion to a Global Policy to meet this requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71385'
  tag rid: 'SV-86009r1_rule'
  tag stig_id: 'CAGW-GW-000480'
  tag gtitle: 'SRG-NET-000251-ALG-000131'
  tag fix_id: 'F-77703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
