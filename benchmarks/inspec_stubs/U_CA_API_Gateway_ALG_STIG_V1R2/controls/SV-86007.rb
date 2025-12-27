control 'SV-86007' do
  title 'The CA API Gateway providing content filtering must send an immediate (within seconds) alert to the system administrator, at a minimum, in response to malicious code detection.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, which will impede the ability to perform forensic analysis and detect rate-based and other anomalies.

The ALG generates an immediate (within seconds) alert that notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since it will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident.

The CA API Gateway must be configured to integrate with an ICAP-enabled Intrusion Detection System such as McAfee, Sophos, or Symantec. These systems must be configured in accordance with organizational requirements, including the detection of malicious code. The CA API Gateway must then evaluate the response of the scanning from the ICAP-enabled Intrusion Detection System and send an email to the system administrator.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require an alert to be sent when malicious code is detected. 

Verify the "Scan Using ICAP-Enabled Antivirus" Assertion is included in the policy and the "Send Email Alert" Assertion is included after the "ICAP-Enabled Antivirus" Assertion with the results of the response variable set in the "ICAP-Enabled Antivirus" Assertion included in the message body of the Assertion. 

Additionally, to avoid receiving emails on all items scanned, the policy should be configured to only send an email alert upon detection of malicious code within the response of the "ICAP-Enabled AntiVirus" Assertion. 

If neither Assertion is present, check to see if it has been added to a Global Policy. 

If the Assertions are not present in either Global or Registered Services policy, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require an alert to be sent when malicious code is detected. 

Verify/add the "Scan Using ICAP-Enabled Antivirus" Assertion and the "Send Email Alert". 

Configure the "Scan Using ICAP-Enabled Antivirus" Assertion as per organizational requirements.

Position the "Send Email Alert" Assertion after the "ICAP-Enabled Antivirus" Assertion with the results of the response variable set in the "ICAP-Enabled Antivirus" Assertion included in the message body of the "Send Email Alert" Assertion.

Additionally, to avoid receiving emails on all items scanned, configure the policy to only send an email alert upon detection of malicious code within the response of the "ICAP-Enabled AntiVirus" Assertion.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71383'
  tag rid: 'SV-86007r1_rule'
  tag stig_id: 'CAGW-GW-000470'
  tag gtitle: 'SRG-NET-000249-ALG-000146'
  tag fix_id: 'F-77701r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
