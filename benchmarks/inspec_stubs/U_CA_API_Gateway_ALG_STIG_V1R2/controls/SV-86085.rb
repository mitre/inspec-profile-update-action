control 'SV-86085' do
  title 'The ALG providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when new active propagation of malware infecting
DoD systems or malicious code adversely affecting the operations and/or security
of DoD systems is detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity-level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require an alert to be sent when malicious code/malware is detected. 

Verify the "Scan Using ICAP-Enabled Antivirus" Assertion is included in the policy and that the "Send Email Alert" Assertion is included after the "ICAP-Enabled Antivirus" Assertion, with the results of the response variable set in the "ICAP-Enabled Antivirus" Assertion included in the message body of the Assertion. 

Additionally, to avoid receiving emails on all items scanned, the policy should be configured to only send an email alert upon detection of malicious code/malware within the response of the "ICAP-Enabled AntiVirus" Assertion. 

If neither Assertion is present, check to see if it has been added to a Global Policy. 

If the Assertions are not present in either Global or Registered Services policy, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that require an alert to be sent when malicious code/malware is detected. 

Verify/add the "Scan Using ICAP-Enabled Antivirus" Assertion and the "Send Email Alert". 

Configure the "Scan Using ICAP-Enabled Antivirus" Assertion as per organizational requirements and position the "Send Email Alert Assertion after the "ICAP-Enabled Antivirus" Assertion, with the results of the response variable set in the "ICAP-Enabled Antivirus" Assertion included in the message body of the "Send Email Alert" Assertion. 

Additionally, to avoid receiving emails on all items scanned, the policy should be configured to only send an email alert upon detection of malicious code within the response of the "ICAP-Enabled AntiVirus" Assertion. If desired, these Assertions can be added to a Global Policy.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71461'
  tag rid: 'SV-86085r1_rule'
  tag stig_id: 'CAGW-GW-000820'
  tag gtitle: 'SRG-NET-000392-ALG-000149'
  tag fix_id: 'F-77781r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
