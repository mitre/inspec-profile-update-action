control 'SV-80917' do
  title 'The Juniper Networks SRX Series Gateway IDPS must generate an alert to, at a minimum, the ISSO and ISSM when root-level intrusion events that provide unauthorized privileged access are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category I, II, IV, and VII detection events) will require an alert when an event is detected.

Alerts messages must include a severity level indicator or code as an indicator of the criticality of the incident. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The Juniper SRX IDPS can be configured for email alerts.)
  desc 'check', 'Verify an attack group or rule is configured.

[edit]
show security idp policies

If an attack group or rules are not configured to detect root-level intrusion attacks or the match condition is not configured for an alert, this is a finding.'
  desc 'fix', 'Configure an attack group for "ROOT" attacks in the signature database which are recommended. Consult the Junos Security Intelligence Center IDP signatures website for a list and details of each attack, along with recommended action upon detection. Then add the attack group to a policy.

Specify the attack group as match criteria in an IDP policy rule.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67073r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66427'
  tag rid: 'SV-80917r1_rule'
  tag stig_id: 'JUSX-IP-000024'
  tag gtitle: 'SRG-NET-000392-IDPS-00216'
  tag fix_id: 'F-72503r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
