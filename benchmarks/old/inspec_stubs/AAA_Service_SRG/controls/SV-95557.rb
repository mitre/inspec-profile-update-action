control 'SV-95557' do
  title 'AAA Services must be configured to notify system administrators and ISSO of account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Sending notification of account enabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, the AAA or directory services must notify the appropriate individuals so they can investigate the event. 

AAA Services may not have built-in capabilities to notify the administrators and ISSO and may require the use of third-party tools (e.g. SNMP, SIEM) to perform the notification.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to notify system administrator and ISSO of account enabling actions.

If AAA Services are not configured to notify the system administrator and ISSO of account enabling actions, this is a finding.'
  desc 'fix', 'Configure AAA Services to notify system administrator and ISSO of account enabling actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80583r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80847'
  tag rid: 'SV-95557r1_rule'
  tag stig_id: 'SRG-APP-000320-AAA-000180'
  tag gtitle: 'SRG-APP-000320-AAA-000180'
  tag fix_id: 'F-87701r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
