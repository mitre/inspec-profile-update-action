control 'SV-77795' do
  title 'Virtual switch VLANs must be fully documented and have only the required VLANs.'
  desc 'When defining a physical switch port for trunk mode, only specified VLANs must be configured on the VLAN trunk link. The risk with not fully documenting all VLANs on the vSwitch is that it is possible that a physical trunk port might be configured without needed VLANs, or with unneeded VLANs, potentially enabling an administrator to either accidentally or maliciously connect a VM to an unauthorized VLAN.'
  desc 'check', "Note: This check refers to an entity outside the physical scope of the ESXi server system. The configuration of upstream physical switches must be documented to ensure that unneeded VLANs are configured for all physical ports connected to ESXi hosts. Inspect the documentation and verify that the documentation is updated on a regular basis and/or whenever modifications are made to either ESXi hosts or the upstream physical switches. Alternatively, log in to the physical switch and verify that only needed VLANs are configured for all physical ports connected to ESXi hosts.

If the physical switch's configuration is trunked VLANs that are not used by ESXi for all physical ports connected to ESXi hosts, this is a finding."
  desc 'fix', 'Note: This fix refers to an entity outside the scope of the ESXi server system.

Remove any VLANs trunked across physical ports connected to ESXi hosts that are not in use.'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63305'
  tag rid: 'SV-77795r1_rule'
  tag stig_id: 'ESXI-06-000068'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
