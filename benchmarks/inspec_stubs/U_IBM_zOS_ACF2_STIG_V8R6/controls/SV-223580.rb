control 'SV-223580' do
  title 'IBM z/OS system administrator must develop a procedure to terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.'
  desc 'If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.'
  desc 'check', 'Ask the system administrator for the procedure to terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to terminate all sessions and network connections related to nonlocal maintenance when nonlocal maintenance is completed.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25253r500875_chk'
  tag severity: 'medium'
  tag gid: 'V-223580'
  tag rid: 'SV-223580r533198_rule'
  tag stig_id: 'ACF2-OS-002410'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-25241r500876_fix'
  tag 'documentable'
  tag legacy: ['V-97865', 'SV-106969']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
