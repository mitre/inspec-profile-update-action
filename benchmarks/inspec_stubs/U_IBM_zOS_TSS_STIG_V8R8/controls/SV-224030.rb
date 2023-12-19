control 'SV-224030' do
  title 'The IBM z/OS System Administrator must develop a process to notify Information System Security Officers (ISSOs) of account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable an existing disabled account. Sending notification of account enabling actions to the System Administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, operating systems must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented processes to notify the Information System Security Officers (ISSOs) of account enabling actions.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify the Information System Security Officers (ISSOs) of account enabling actions.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25703r516489_chk'
  tag severity: 'medium'
  tag gid: 'V-224030'
  tag rid: 'SV-224030r561402_rule'
  tag stig_id: 'TSS0-OS-000340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25691r516490_fix'
  tag 'documentable'
  tag legacy: ['SV-107873', 'V-98769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
