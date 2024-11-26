control 'SV-86083' do
  title 'The CA API Gateway providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when Denial of Service (DoS) incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity-level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.

The CA API Gateway must be configured to send an email upon detection of an event such as a denial of service after exceeding a rate limit defined by an administrator in accordance with organizational requirements through the use of a "Send Email Alert" Assertion that can be added to all Registered Services requiring email notifications or to a global policy defining a rate limit.)
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services requiring email notifications for denial of service attacks. 

Verify the "Send Email Alert" Assertion has been included in the policy at the required decision points, usually after an "Apply Rate Limit" or "Apply Throughput Quota" Assertion within the policy as per organizational requirements. 

If it is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click the Registered Services requiring email notifications for DoS attacks that did not have the "Send Email Alert" Assertion included. 

Add the "Send Email Alert" Assertion to the policy at the required decision points, usually after an "Apply Rate Limit" or "Apply Throughput Quota" Assertion within the policy as per organizational requirements.

Optionally, the "Send Email Alert" Assertion can be added to a Global Policy detecting DoS attacks.'
  impact 0.3
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71849r1_chk'
  tag severity: 'low'
  tag gid: 'V-71459'
  tag rid: 'SV-86083r1_rule'
  tag stig_id: 'CAGW-GW-000810'
  tag gtitle: 'SRG-NET-000392-ALG-000148'
  tag fix_id: 'F-77779r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
