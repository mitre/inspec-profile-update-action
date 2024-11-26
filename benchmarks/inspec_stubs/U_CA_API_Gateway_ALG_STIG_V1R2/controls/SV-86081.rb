control 'SV-86081' do
  title 'The CA API Gateway providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when user-level intrusions that provide non-privileged access are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity-level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.

The CA API Gateway must be configured to send an email upon detection of an event such as a user trying to gain privileged access to a back-end service through the use of a "Send Email Alert" Assertion within all Registered Services requiring email notifications for events such as user-level intrusions.)
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services requiring email notifications for user-level intrusions. 

Verify the "Send Email Alert" Assertion has been included in the policy as per organizational requirements. 

If it is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click the Registered Services requiring email notifications for user-level intrusions that did not have the "Send Email Alert" Assertion included.

Add the "Send Email Alert" Assertion to the policy and configure as per organizational requirements.'
  impact 0.3
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71847r1_chk'
  tag severity: 'low'
  tag gid: 'V-71457'
  tag rid: 'SV-86081r1_rule'
  tag stig_id: 'CAGW-GW-000800'
  tag gtitle: 'SRG-NET-000392-ALG-000147'
  tag fix_id: 'F-77777r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
