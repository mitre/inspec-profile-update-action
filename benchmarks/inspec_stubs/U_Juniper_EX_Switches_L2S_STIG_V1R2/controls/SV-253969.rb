control 'SV-253969' do
  title 'The Juniper EX switch must not use the default VLAN for management traffic.'
  desc 'By default, all unassigned interfaces are placed into the default VLAN and if used for management, could unintentionally expose sensitive traffic or protected resources to unauthorized devices.'
  desc 'check', 'Review the switch configuration and verify that the default VLAN is not used to access the switch for management.

Verify access interfaces used for management are assigned to an appropriate VLAN as in the example below.
[edit interfaces]
<interface name> {
    unit 0 {
        family ethernet-switching {
            interface-mode access;
            vlan {
                members <vlan name>;
            }
        }
    }
}

If the default VLAN is being used to access the switch, this is a finding.'
  desc 'fix', 'Configure the switch for management access to use a VLAN other than the default VLAN.

set interfaces <interface name> unit 0 family ethernet-switching interface-mode access
set interfaces <interface name> unit 0 family ethernet-switching vlan members <vlan name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57421r843938_chk'
  tag severity: 'medium'
  tag gid: 'V-253969'
  tag rid: 'SV-253969r843940_rule'
  tag stig_id: 'JUEX-L2-000220'
  tag gtitle: 'SRG-NET-000512-L2S-000010'
  tag fix_id: 'F-57372r843939_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
