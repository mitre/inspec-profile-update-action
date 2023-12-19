control 'SV-234137' do
  title 'The FortiGate firewall must generate traffic log entries containing information to establish the network location where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as network element components, modules, device identifiers, node names, and functionality. 

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Forward Traffic, or Local Traffic.
3. Double-click on an Event to view Log Details.
4. Verify traffic log events contain source and destination IP addresses, and interfaces.

In addition to System log settings, verify that individual firewall policies are configured with most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all Policy rules are configured with Logging Options set to log All Sessions (for most verbose logging).

If the traffic log events do not contain source and destination IP addresses, or interfaces, this is a finding.'
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super-Admin privilege.

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
3. For each configured policy set the following: 
     # config firewall {policy|policy6}
     #   edit {policyid}
     #       set logtraffic enable
     # end

The {} indicate the object is defined by the organization policy.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37322r611409_chk'
  tag severity: 'medium'
  tag gid: 'V-234137'
  tag rid: 'SV-234137r628776_rule'
  tag stig_id: 'FNFG-FW-000030'
  tag gtitle: 'SRG-NET-000076-FW-000011'
  tag fix_id: 'F-37287r611410_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
