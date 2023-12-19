control 'SV-26212' do
  title 'The PF_LLC protocol handler must not be installed.'
  desc 'The Packet Family - Logical Link Control (PF_LLC) protocol handler provides a sockets interface for applications to communicate over the LLC sublayer.  This interface is not commonly used and may increase the attack surface of the system.'
  desc 'check', 'If the PF_LLC protocol handler is not available as an optional software package for the system, this is not applicable.
If the PF_LLC protocol handler is installed, this is a finding.'
  desc 'fix', 'Uninstall the PF_LLC protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29292r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22537'
  tag rid: 'SV-26212r1_rule'
  tag stig_id: 'GEN000000-LNX007620'
  tag gtitle: 'GEN000000-LNX007620'
  tag fix_id: 'F-26324r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
