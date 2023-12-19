control 'SV-250550' do
  title 'All physical switch ports must be configured with spanning tree disabled.'
  desc 'Due to the integration of the ESXi Server into the physical network, the physical network (switch) adaptors must have spanning tree disabled or portfast configured for external switches, because VMware virtual switches do not support STP. Virtual switch uplinks do not create loops within the physical switch network. If these are not set, potential performance and connectivity issues might arise.'
  desc 'check', "Note that this check refers to an entity outside the physical scope of the ESXi server system. The configuration of upstream physical switches must be documented to ensure that spanning tree protocol is disabled and/or portfast is configured for all physical ports connected to ESXi hosts. Inspect the documentation and verify that the documentation is updated on an organization defined frequency and/or whenever modifications are made to either ESXi hosts or the upstream physical switches. Alternatively, log in to the physical switch and verify that spanning tree protocol is disabled and/or portfast is configured for all physical ports connected to ESXi hosts.

If the physical switch's spanning tree protocol is not disabled or portfast is not configured for all physical ports connected to ESXi hosts, this is a finding."
  desc 'fix', 'Note that this check refers to an entity outside the scope of the ESXi server system. Document the upstream physical switch configuration for spanning tree protocol disablement and/or portfast configuration for all physical ports connected to ESXi hosts. Log in to the physical switch(es) and disable spanning tree protocol and/or configure portfast for all physical ports connected to ESXi hosts. Update the documentation on an organization defined frequency or whenever modifications are made to either ESXi hosts or the upstream physical switches.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53985r798647_chk'
  tag severity: 'low'
  tag gid: 'V-250550'
  tag rid: 'SV-250550r798649_rule'
  tag stig_id: 'ESXI5-VMNET-000008'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53939r798648_fix'
  tag 'documentable'
  tag legacy: ['SV-51223', 'V-39365']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
