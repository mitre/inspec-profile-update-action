control 'SV-217092' do
  title 'The Juniper multicast Designated Router (DR) must be configured to set the shortest-path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.'
  desc 'ASM can have many sources for the same groups (many-to-many). For many receivers, the path via the RP may not be ideal compared with the shortest path from the source to the receiver. By default, the last-hop router will initiate a switch from the shared tree to a source-specific SPT to obtain lower latencies. This is accomplished by the last-hop router sending an (S, G) Protocol Independent Multicast (PIM) Join toward S (the source).

When the last-hop router begins to receive traffic for the group from the source via the SPT, it will send a PIM Prune message to the RP for the (S, G). The RP will then send a Prune message toward the source. The SPT switchover becomes a scaling issue for large multicast topologies that have many receivers and many sources for many groups because (S, G) entries require more memory than (*, G). Hence, it is imperative to minimize the amount of (S, G) state to be maintained by increasing the threshold that determines when the SPT switchover occurs.'
  desc 'check', 'Review the multicast last-hop router configuration to verify that the SPT switchover threshold is set to infinity for all or specific multicast groups and sources.

Verify that an infinity policy has been enabled for PIM.

protocols {
    …
    …
    …
    }
    pim {
        spt-threshold {
            infinity SPT_INFINITY;
        }
    }
}

Verify that the infinity policy defines specific multicast groups and sources or all multicast groups and sources as shown in the example below.

policy-options {
    …
    …
    …
    }
    policy-statement SPT_INFINITY {
        term ALL_GROUPS {
            from {
                route-filter 234.0.0.0/8 orlonger;
            }
            then accept;
        }
    }
}

If any multicast router is not configured to set the SPT threshold to infinity to minimalize (S, G) state, this is a finding.'
  desc 'fix', 'Configure the multicast router to increase the SPT threshold or set it to infinity to minimalize (S, G) state within the multicast topology where ASM is deployed.

Configure a policy statement to set SPT threshold to infinity for all multicast groups or only specific groups and sources.

[edit policy-options]
set policy-statement SPT_INFINITY term ALL_GROUPS from route-filter 234.0.0.0/8 orlonger
set policy-statement SPT_INFINITY term ALL_GROUPS then accept

Apply the SPT infinity policy.

[edit protocols pim]
set spt-threshold infinity SPT_INFINITY'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18321r297144_chk'
  tag severity: 'medium'
  tag gid: 'V-217092'
  tag rid: 'SV-217092r639663_rule'
  tag stig_id: 'JUNI-RT-000880'
  tag gtitle: 'SRG-NET-000362-RTR-000123'
  tag fix_id: 'F-18319r297145_fix'
  tag 'documentable'
  tag legacy: ['SV-101177', 'V-90967']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
