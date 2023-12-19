control 'SV-253968' do
  title 'The Juniper EX switch must be configured to prune the default VLAN from all trunked interfaces that do not require it.'
  desc 'All unassigned interfaces are placed into the default VLAN and devices connected to enabled, but unassigned interfaces can communicate within that VLAN. Although the default VLAN is not automatically assigned to any trunked interface, if the default VLAN must be trunked or a misconfigured trunk unintentionally includes the default VLAN, unauthorized devices connected to enabled but unassigned access interfaces could gain network connectivity beyond the local switch.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is pruned from trunk links that do not require it.

[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
            interface-mode trunk;
            vlan {
                members [ vlan_name ... vlan_name ];
            }
        }
    }
}

If the default VLAN is not pruned from trunk links that should not be transporting frames for that VLAN, this is a finding.'
  desc 'fix', 'Remove unnecessary VLANs from trunked interfaces.

delete interfaces <trunked interface name> unit 0 family ethernet-switching vlan members <default | other unnecessary VLAN name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57420r843935_chk'
  tag severity: 'medium'
  tag gid: 'V-253968'
  tag rid: 'SV-253968r843937_rule'
  tag stig_id: 'JUEX-L2-000210'
  tag gtitle: 'SRG-NET-000512-L2S-000009'
  tag fix_id: 'F-57371r843936_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
