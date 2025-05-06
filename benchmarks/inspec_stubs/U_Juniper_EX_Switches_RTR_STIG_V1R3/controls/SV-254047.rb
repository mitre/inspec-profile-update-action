control 'SV-254047' do
  title 'The Juniper perimeter router must be configured to have Link Layer Discovery Protocols (LLDPs) disabled on all external interfaces.'
  desc 'LLDPs are primarily used to obtain protocol addresses of neighboring devices and discover platform capabilities of those devices. Use of SNMP with the LLDP Management Information Base (MIB) allows network management applications to learn the device type and the SNMP agent address of neighboring devices, thereby enabling the application to send SNMP queries to those devices. LLDPs are also media- and protocol-independent as they run over the data link layer; therefore, two systems that support different network-layer protocols can still learn about each other. Allowing LLDP messages to reach external network nodes is dangerous as it provides an attacker a method to obtain information of the network infrastructure that can be useful to plan an attack.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review all router configurations to ensure LLDPs are not included in the global configuration or LLDPs are not included for each active external interface. Examples of LLDPs are Cisco Discovery Protocol (CDP), Link Layer Discovery Protocol (LLDP), and Link Layer Discovery Protocol - Media Endpoint Discovery (LLDP-MED). Junos does not support CDP, but supports both LLDP and LLDP-MED, configured at [edit protocols]. Verify external interfaces are either not configured or explicitly disabled. For example:

To globally disable LLDP and LLDP-MED:
[edit protocols]
<no LLDP or LLDP-MED hierarchy>
-or-
lldp {
    interface all {
        disable;
    }
}
lldp-med {
    interface all {
        disable;
    }
}

If LLDP or LLDP-MED is authorized, verify external interfaces are not configured or are explicitly disabled. For example:
[edit protocols]
lldp {
    interface all {
        disable;
    }
    interface ge-0/0/0; <<< Verify ge-0/0/0 is not an external interface.
    interface ge-0/0/1 {
        disable; <<< Assuming ge-0/0/1 is an external interface, it is disabled globally (interface all disable) or explicitly disabled as shown.
    }
}
lldp-med {
    interface all {
        disable;
    interface ge-0/0/0; <<< Verify ge-0/0/0 is not an external interface.
    interface ge-0/0/1 {
        disable; <<< Assuming ge-0/0/1 is an external interface, it is disabled globally (interface all disable) or explicitly disabled as shown.
    }
}

Note: Both LLDP and LLDP-MED are globally disabled on all interfaces but Junos will apply the most specific configuration. Therefore, both LLDP and LLDP-MED are enabled only on ge-0/0/0 and disabled on all other interfaces as configured in the example.

If LLDPs are configured globally or on any external interface, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Disable LLDPs on all external interfaces.

set protocols lldp interface all disable
set protocols lldp interface <interior interface>
set protocols lldp interface <exterior interface> disable

set protocols lldp-med interface all disable
set protocols lldp-med interface <interior interface>
set protocols lldp-med interface <exterior interface> disable

Note: The <exterior interface> disable command is not required if LLDP and LLDP-MED are globally disabled. However, the configured protocol status may be more apparent if each exterior interface is explicitly disabled.'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57499r844172_chk'
  tag severity: 'low'
  tag gid: 'V-254047'
  tag rid: 'SV-254047r844174_rule'
  tag stig_id: 'JUEX-RT-000750'
  tag gtitle: 'SRG-NET-000364-RTR-000111'
  tag fix_id: 'F-57450r844173_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
