control 'SV-223802' do
  title 'IBM z/OS system administrator must develop a procedure to terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.'
  desc 'If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.'
  desc 'check', 'Ask the system administrator for the procedure to terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25475r515094_chk'
  tag severity: 'medium'
  tag gid: 'V-223802'
  tag rid: 'SV-223802r604139_rule'
  tag stig_id: 'RACF-OS-000480'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-25463r515095_fix'
  tag 'documentable'
  tag legacy: ['V-98311', 'SV-107415']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
