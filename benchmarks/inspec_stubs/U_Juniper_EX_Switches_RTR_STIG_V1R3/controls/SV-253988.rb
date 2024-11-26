control 'SV-253988' do
  title 'The Juniper router must be configured to have all inactive interfaces disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled. For logical interfaces, delete those that are on inactive interfaces and delete logical interfaces that are themselves inactive. If the logical interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'Review the router configuration and verify unused interfaces are not configured (implicitly disabled) or are explicitly disabled. If explicitly disabling interfaces, verify multiple interfaces are disabled with the "interface-range" command or separately at each interface declaration.

[edit interfaces]
interface-range DISABLED_INTERFACES {
    member <interface name>;
    member-range <first interface> to <last interface>;
    disable;
}
<interface name> {
    disable;
}

Note: Individually disabled interfaces should not be included in any "interface-range" stanza. The "member-range" directive assigns the configured parameter(s) to contiguously numbered interfaces.

Junos lists interfaces in order so a "missing" interface is not enabled. For instance, if ge-0/0/0 and ge-0/0/2 are configured, but there is no individual ge-0/0/1 stanza and that interface is not a member of an interface-range, then ge-0/0/1 is implicitly disabled.

If an interface is not being used but is configured or enabled, this is a finding.'
  desc 'fix', 'Disable inactive interfaces.

delete interfaces <interface name>
-or-
set interfaces <interface name> disable
-or-
set interfaces interface-range DISABLED_INTERFACES member <interface name>
set interfaces interface-range DISABLED_INTERFACES member-range <first interface name> to <last interface name>
set interfaces interface-range DISABLED_INTERFACES disable'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57440r843995_chk'
  tag severity: 'low'
  tag gid: 'V-253988'
  tag rid: 'SV-253988r843997_rule'
  tag stig_id: 'JUEX-RT-000160'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-57391r843996_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
