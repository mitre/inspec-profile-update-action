control 'SV-253957' do
  title 'The Juniper EX switch must be configured to enable STP Loop Protection on all non-designated STP switch ports.'
  desc 'The Spanning Tree Protocol (STP) Loop Protection feature provides additional protection against STP loops. An STP loop is created when an STP blocking port in a redundant topology erroneously transitions to the forwarding state. In its operation, STP relies on continuous reception and transmission of BPDUs based on the port role. The designated port transmits BPDUs, and the non-designated port receives BPDUs. When one of the ports in a physically redundant topology no longer receives BPDUs, the STP conceives that the topology is loop free. Eventually, the blocking port from the alternate or backup port becomes a designated port and moves to a forwarding state. This situation creates a loop. The loop protection feature makes additional checks. If BPDUs are not received on a non-designated port and loop protection is enabled, that port is moved into the STP loop-inconsistent blocking state.'
  desc 'check', 'Review the switch configuration to verify that STP Loop Protection is enabled on all non-designated STP switch ports.

Verify STP Loop Protection for RSTP and VSTP.
[edit protocols]
rstp {
    interface <interface name> {
        bpdu-timeout-action {
            block;
        }
    }
}
vstp {
    interface <interface name> {
        bpdu-timeout-action {
            block;
        }
    }
}

Verify Loop Protection for all instances on an MSTP interface:
[protocols]
mstp {
    interface <interface name> {
        bpdu-timeout-action {
            block;
        }
    }
}

Note: Loop Protection and Root Protection are mutually exclusive and cannot be simultaneously configured on the same interface.

If STP Loop Protection is not configured on non-designated STP ports, this is a finding.'
  desc 'fix', 'Configure the switch to have STP Loop Protection enabled on all non-designated STP interfaces.

RSTP or VSTP non-designated interface loop protection:
set protocols rstp interface <interface name> bpdu-timeout-action block
set protocols vstp interface <interface name> bpdu-timeout-action block

All instances on an MSTP interface:
set protocols mstp interface <interface name> bpdu-timeout-action block

Note: Loop Protection and Root Protection are mutually exclusive and cannot be simultaneously configured on the same interface.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57409r843902_chk'
  tag severity: 'medium'
  tag gid: 'V-253957'
  tag rid: 'SV-253957r843904_rule'
  tag stig_id: 'JUEX-L2-000100'
  tag gtitle: 'SRG-NET-000362-L2S-000023'
  tag fix_id: 'F-57360r843903_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
