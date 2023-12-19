control 'SV-234148' do
  title 'The FortiGate firewall must fail to a secure state if the firewall filtering functions fail unexpectedly.'
  desc 'Firewalls that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection. Failure to a known safe state helps prevent systems from failing to a state that may cause unauthorized access to make changes to the firewall filtering functions. 

This applies to the configuration of the gateway or network traffic security function of the device. Abort refers to stopping the firewall filtering function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show ips global | grep -i fail-open
     # show system global | grep -i failopen

If ips fail-open is set to enable or av-failopen is not set to off or av-failopen-session is not set to disable, this is a finding.'
  desc 'fix', 'FortiGate will inherently fail closed upon a power failure. Additionally, the FortiOS kernel enters conserve mode when memory use reaches the red threshold (default 88 percent memory use). When the red threshold is reached, FortiOS functions that react to conserve mode, such as the antivirus transparent proxy, apply conserve mode based on configured conserve mode settings. Additionally, FortiOS generates conserve mode log messages and SNMP traps, and a conserve mode banner appears on the GUI. If memory use reaches the extreme threshold (95 percent memory used), new sessions are dropped and red threshold conserve mode actions continue.

Conserve mode actions for filtering are configured as follows:

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config ips global
     #    set fail-open disable
     # end
     # config system global
     #    set av-failopen off
     #    set av-failopen-session disable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37333r611442_chk'
  tag severity: 'medium'
  tag gid: 'V-234148'
  tag rid: 'SV-234148r628776_rule'
  tag stig_id: 'FNFG-FW-000090'
  tag gtitle: 'SRG-NET-000235-FW-000133'
  tag fix_id: 'F-37298r611443_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
