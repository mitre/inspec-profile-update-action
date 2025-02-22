control 'SV-203691' do
  title 'The operating system must notify system administrators and ISSOs of account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to enable an existing disabled account.  Sending notification of account enabling actions to the system administrator and ISSO is one method for mitigating this risk.  Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, operating systems must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system notifies the System Administrator and Information System Security Officer(s) when accounts are created, or enabled when previously disabled. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to notify the System Administrator(s) and Information System Security Officer(s) when accounts are created, or enabled when previously disabled.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3816r375020_chk'
  tag severity: 'medium'
  tag gid: 'V-203691'
  tag rid: 'SV-203691r379471_rule'
  tag stig_id: 'SRG-OS-000304-GPOS-00121'
  tag gtitle: 'SRG-OS-000304'
  tag fix_id: 'F-3816r375021_fix'
  tag 'documentable'
  tag legacy: ['V-57223', 'SV-71483']
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
