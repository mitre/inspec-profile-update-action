control 'SV-234138' do
  title 'The FortiGate firewall must generate traffic log entries containing information to establish the source of the events, such as the source IP address at a minimum.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the traffic log events must also identify sources of events, such as IP addresses, processes, and node or device names.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Forward Traffic or Local Traffic.
3. Double-click on an Event to view Log Details.
4. Verify traffic log events contain source and destination IP addresses, and interfaces.

In addition to System log settings, verify that individual IPv4 policies are configured with most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all Policy rules are configured with Logging Options set to log All Sessions (for most verbose logging).

If the log events do not contain IP address of source devices, this is a finding.'
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super- or Log-and-Report-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Click All for the Event Logging and Local Traffic Log options (for most verbose logging), or Click Customize and choose granular logging options to meet organization needs.
4. Scroll to UUIDs in Traffic Log and toggle Policy and Address buttons to enable.
5. Click Apply.

In addition to these log settings, configure individual firewall policies with the most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. For each policy, configure Logging Options to log All Sessions (for most verbose logging).
4. Confirm each created Policy is Enabled.
5. Click OK.

or

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log eventfilter
     #    set event enable
     #    set system enable
     #    set endpoint enable
     #    set user enable
     #    set security-rating enable
     # end
     # config firewall policy
     #   edit 0
     #        set srcintf {interface_name_1}
     #        set dstintf {interface_name_2}
     #        set srcaddr {address_a}
     #        set dstaddr {address_b}
     #        set schedule {always}
     #        set service {services required by site policy}
     #        set action {accept}
     #        set logtraffic enable
     #    next
     # end

The {} indicate the object is defined by the organization policy.'
  impact 0.3
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37323r611412_chk'
  tag severity: 'low'
  tag gid: 'V-234138'
  tag rid: 'SV-234138r628776_rule'
  tag stig_id: 'FNFG-FW-000035'
  tag gtitle: 'SRG-NET-000077-FW-000012'
  tag fix_id: 'F-37288r611413_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
