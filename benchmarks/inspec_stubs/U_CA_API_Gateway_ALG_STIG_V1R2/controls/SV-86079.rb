control 'SV-86079' do
  title 'The CA API Gateway providing content filtering must generate a notification on the console when root-level intrusion events that attempt to provide unauthorized privileged access are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity-level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.

The CA API Gateway is configured by default to only allow 5 failed attempts to log on to the Gateway console. After 5 attempts, all accounts will be locked for 20 minutes. Upon the next successful logon as a privileged administrator, such as root on the console, a message will appear stating "there were x failed logon attempts since the last successful login".)
  desc 'check', %q(Using an SSH client, attempt to log on to the CA API Gateway using the root user. The attempt will fail as root logons from a remote SSH client are disabled by default. 

On the main console of the CA API Gateway, log on with the root user and notice the message stating "There were 'x' failed login attempts..." and "Last failed login: date time from address on ssh:notty". 

If the logon is allowed or the message does not appear, this is a finding.)
  desc 'fix', 'There should be no fix for this, as by default the CA API Gateway is configured to disallow remote logons by the root user and detect when an attempt to logon as root has occurred.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71455'
  tag rid: 'SV-86079r1_rule'
  tag stig_id: 'CAGW-GW-000790'
  tag gtitle: 'SRG-NET-000392-ALG-000143'
  tag fix_id: 'F-77775r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
