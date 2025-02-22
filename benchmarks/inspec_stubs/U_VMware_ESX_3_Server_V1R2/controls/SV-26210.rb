control 'SV-26210' do
  title 'The PF_LLC protocol handler must not be bound to the network stack.'
  desc 'The Packet Family - Logical Link Control (PF_LLC) protocol handler provides a sockets interface for applications to communicate over the LLC sublayer.  This interface is not commonly used and may increase the attack surface of the system.'
  desc 'check', 'If the system does not have a PF_LLC protocol handler, this is not applicable.

Determine if the PF_LLC protocol handler is bound to the network stack.  If it is, this is a finding.'
  desc 'fix', 'Unbind the PF_LLC protocol handler from the network stack.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29134r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22535'
  tag rid: 'SV-26210r1_rule'
  tag stig_id: 'GEN000000-LNX007580'
  tag gtitle: 'GEN000000-LNX007580'
  tag fix_id: 'F-26140r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
