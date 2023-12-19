control 'SV-86077' do
  title 'The CA API Gateway providing content filtering must send an alert to, at a minimum, the ISSO and ISSM when detection events occur.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

The CA API Gateway provides content inspection services in real time. These systems generate alerts when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.

The CA API Gateway must send an email upon detection of an event though the use of a "Send Email Alert" Assertion added to the Registered Services requiring email notifications.)
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services requiring email notifications. 

Verify the "Send Email Alert" Assertion has been included in the policy at the required decision points within the policy as per organizational requirements. 

If it is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click any of the Registered Services that did not include the "Send Email Alert" Assertion. 

Add the "Send Email Alert" Assertion to the policy and configure the parameters for the Assertion to meet organizational requirements. 

Note that the Assertion should be added after a detection event occurs, such as a threat detection event detecting a SQL injection, and will most likely be included as part of either an "At least one assertion must evaluate to true" or "All Assertions must evaluate to true" policy logic folder.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71453'
  tag rid: 'SV-86077r1_rule'
  tag stig_id: 'CAGW-GW-000770'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-77773r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
