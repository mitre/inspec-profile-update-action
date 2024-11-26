control 'SV-68923' do
  title 'The ALG providing content filtering must send an alert to, at a minimum, the ISSO and ISSM when detection events occur.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

In accordance with CCI-001242, the ALG which provides content inspection services are a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel."
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG sends an alert to, at a minimum, the ISSO and ISSM when detection events occur.

If the ALG does not send an alert to, at a minimum, the ISSO and ISSM when detection events from real-time monitoring of communications traffic occur, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to send an alert to, at a minimum, the ISSO and ISSM when detection events occur.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55297r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54677'
  tag rid: 'SV-68923r1_rule'
  tag stig_id: 'SRG-NET-000392-ALG-000141'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-59533r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
