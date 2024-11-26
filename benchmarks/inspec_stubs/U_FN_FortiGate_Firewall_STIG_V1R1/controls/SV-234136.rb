control 'SV-234136' do
  title 'The FortiGate firewall must generate traffic log entries containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

To compile an accurate risk assessment and provide forensic analysis of network traffic patterns, it is essential for security personnel to know when flow control events occurred (date and time) within the infrastructure.

Associating event types with detected events in the network traffic logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Events, or Local Traffic.
3. Verify events are generated containing date, time, and alert level related to System and Local Traffic Log.

In addition to System log settings, verify individual firewall policies are configured with most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all Policy rules are configured with Logging Options set to log All Sessions (for most verbose logging).

If the log events do not contain information to establish date and time, this is a finding.'
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Click All for the Event Logging and Local Traffic Log options (for most verbose logging), or Click Customize and choose granular logging options to meet organization needs.
4. Click Apply.

In addition to these log settings, configure individual firewall policies with the most suitable Logging Options.
 
1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. For each policy, configure Logging Options to log All Sessions (for most verbose logging).
4. Confirm each created Policy is Enabled.
5. Click OK.

or

1. Open a CLI console.
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
     #        set service {service required by site policy}
     #        set action {accept}
     #        set logtraffic enable
     #    next
     # end

The {} indicate the object is defined by the organization policy.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37321r611406_chk'
  tag severity: 'medium'
  tag gid: 'V-234136'
  tag rid: 'SV-234136r628776_rule'
  tag stig_id: 'FNFG-FW-000025'
  tag gtitle: 'SRG-NET-000075-FW-000010'
  tag fix_id: 'F-37286r611407_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
