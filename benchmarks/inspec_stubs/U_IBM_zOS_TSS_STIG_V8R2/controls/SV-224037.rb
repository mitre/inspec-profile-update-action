control 'SV-224037' do
  title 'IBM z/OS system administrator must develop a procedure to notify System Administrators and ISSOs of account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable an existing disabled account. Sending notification of account enabling actions to the System Administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, operating systems must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system administrator for the procedure to notify system administrators and ISSOs of account enabling actions. If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a documented procedure to notify system administrators and ISSOs of account enabling actions.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25710r516510_chk'
  tag severity: 'medium'
  tag gid: 'V-224037'
  tag rid: 'SV-224037r561402_rule'
  tag stig_id: 'TSS0-OS-000410'
  tag gtitle: 'SRG-OS-000304-GPOS-00121'
  tag fix_id: 'F-25698r516511_fix'
  tag 'documentable'
  tag legacy: ['SV-107885', 'V-98781']
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
