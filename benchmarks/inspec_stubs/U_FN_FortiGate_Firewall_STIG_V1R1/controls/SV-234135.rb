control 'SV-234135' do
  title 'The FortiGate firewall must generate traffic log entries containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the network element logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Local Traffic.
3. Verify events are generated containing date, time, alert level related to System and Local Traffic Log.

In addition to System log settings, verify that individual firewall policies are configured with most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all Policy rules are configured with Logging Options set to log All Sessions (for most verbose logging).

If there are no events generated containing date, time, alert level, user, message type, and other information, this is a finding.'
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
  tag check_id: 'C-37320r611403_chk'
  tag severity: 'medium'
  tag gid: 'V-234135'
  tag rid: 'SV-234135r628776_rule'
  tag stig_id: 'FNFG-FW-000020'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag fix_id: 'F-37285r611404_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
