control 'SV-223766' do
  title 'The IBM z/OS System Administrator (SA) must develop a process to notify Information System Security Officers (ISSOs) of account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable an existing disabled account. Sending notification of account enabling actions to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, operating systems must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented processes to notify the Information System Security Officers (ISSOs) of account enabling actions.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify the Information System Security Officers (ISSOs) of account enabling actions.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25439r514986_chk'
  tag severity: 'medium'
  tag gid: 'V-223766'
  tag rid: 'SV-223766r853611_rule'
  tag stig_id: 'RACF-OS-000100'
  tag gtitle: 'SRG-OS-000304-GPOS-00121'
  tag fix_id: 'F-25427r514987_fix'
  tag 'documentable'
  tag legacy: ['V-98239', 'SV-107343']
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
