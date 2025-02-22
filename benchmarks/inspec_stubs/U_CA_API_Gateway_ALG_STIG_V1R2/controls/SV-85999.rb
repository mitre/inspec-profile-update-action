control 'SV-85999' do
  title 'The CA API Gateway providing content filtering must integrate with an ICAP-enabled Intrusion Detection System that updates malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Malicious code protection mechanisms include, but are not limited to, antivirus and malware detection software. In order to minimize any potential negative impact to the organization caused by malicious code, malicious code must be identified and eradicated. Malicious code includes viruses, worms, trojan horses, and spyware.

The CA API Gateway must be configured to integrate with an ICAP-enabled Intrusion Detection System such as McAfee, Sophos, or Symantec. These systems must then be configured to update their protection mechanisms and signature definitions in accordance with organizational requirements.'
  desc 'check', 'Open the CA API GW - Policy Manager and double-click any of the Registered Services that require updating of malicious code mechanisms and signatures. 

Verify the "Scan Using ICAP-Enabled Antivirus" Assertion is included in the policy. Check that the list of ICAP Servers has been configured to include servers listed in the following format: "icap://<servername:port/avscan". 

Also, verify all other options have been configured in accordance with organizational requirements. If not, check to see if the assertion has been added to a Global Policy and configured properly.

If the "Scan Using ICAP-Enabled Antivirus" Assertion is not present in either Global or Registered Services policy, this is a finding.'
  desc 'fix', 'Open the CA API GW - Policy Manager and double-click any of the Registered Services that did not have the "Scan Using ICAP-Enabled Antivirus" Assertion. 

Add the "Scan Using ICAP-Enabled Antivirus" Assertion. 

Add the list of ICAP Scanning servers to the Server list in the following format: "icap://<servername:port/avscan", and configure the additional parameters for the Assertion in accordance with organizational requirements. 

Click the "Save and Activate" button. 

If the organization requires that all Registered Services require this ability, consider adding the "Scan Using ICAP-Enabled Antivirus" Assertion to a Global Policy to meet this requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71375'
  tag rid: 'SV-85999r1_rule'
  tag stig_id: 'CAGW-GW-000430'
  tag gtitle: 'SRG-NET-000246-ALG-000132'
  tag fix_id: 'F-77689r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
