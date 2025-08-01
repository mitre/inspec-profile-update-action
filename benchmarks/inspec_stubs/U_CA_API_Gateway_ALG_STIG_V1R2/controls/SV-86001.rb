control 'SV-86001' do
  title 'The CA API Gateway providing content filtering must be configured to perform real-time scans of files from external sources at network entry/exit points as they are downloaded and prior to being opened or executed.'
  desc "Malicious code includes viruses, worms, trojan horses, and spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code. Once this code is installed on endpoints within the network, unauthorized users may be able to breach firewalls and gain access to sensitive data.

To guard against malicious code, real-time scans must be performed on files from external sources as they are downloaded and prior to being opened or executed.

The CA API Gateway must be configured to integrate with an ICAP-enabled Intrusion Detection System such as McAfee, Sophos, or Symantec. These systems must be configured in accordance with organizational requirements, which must include the real-time scanning of files from external sources."
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require real-time scanning. 

Verify the "Scan Using ICAP-Enabled Antivirus" Assertion is included in the policy. If it is not, check to see if it has been added to a Global Policy. 

If the Assertion is not present in either Global or Registered Services policy, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that did not have the "Scan Using ICAP-Enabled Antivirus" Assertion.

Add the "Scan Using ICAP-Enabled Antivirus" Assertion, configure the parameters for the Assertion in accordance with organizational requirements, and click the "Save and Activate" button. 

If the organization requires that all Registered Services require the ability to scan files in real time, consider adding the "Scan Using ICAP-Enabled Antivirus" Assertion to a Global Policy to meet this requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71377'
  tag rid: 'SV-86001r1_rule'
  tag stig_id: 'CAGW-GW-000440'
  tag gtitle: 'SRG-NET-000248-ALG-000133'
  tag fix_id: 'F-77695r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
