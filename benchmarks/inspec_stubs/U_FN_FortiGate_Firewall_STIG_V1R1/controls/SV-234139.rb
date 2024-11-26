control 'SV-234139' do
  title 'The FortiGate firewall must generate traffic log entries containing information to establish the outcome of the events, such as, at a minimum, the success or failure of the application of the firewall rule.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results. They also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Forward Traffic or Local Traffic.
3. Double-click on an Event to view Log Details.
4. Verify log events contain status information like success or failure of the application of the firewall rule.

In addition to System log settings, verify that individual IPv4 policies are configured with most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all Policy rules are configured with Logging Options set to log All Sessions (for most verbose logging).

If the log events do not contain status information, like success or failure of the application of the firewall rule, this is a finding.'
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Click All for the Event Logging and Local Traffic Log options (for most verbose logging), or Click Customize and choose granular logging options to meet organization needs.
4. Scroll to UUID in Traffic Log and toggle Policy and Address buttons to enable.
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
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37324r611415_chk'
  tag severity: 'medium'
  tag gid: 'V-234139'
  tag rid: 'SV-234139r628776_rule'
  tag stig_id: 'FNFG-FW-000040'
  tag gtitle: 'SRG-NET-000078-FW-000013'
  tag fix_id: 'F-37289r611416_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
