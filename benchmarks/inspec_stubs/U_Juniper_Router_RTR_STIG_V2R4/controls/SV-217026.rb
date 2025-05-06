control 'SV-217026' do
  title 'The Juniper router must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as router components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured router.'
  desc 'check', 'Review the router configuration to verify that events are logged containing information to establish where the events occurred as shown in the example below.

system {
    host-name XYZ;
    …
    …
    …
    }
    syslog {
        file LOG_FILE {
            any any;
        }
    }
}

If the router is not configured to produce audit records containing information to establish to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the router to log events containing information to establish where the events occurred as shown in the example below.
 
[edit system syslog]
set file LOG_FILE any any'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18255r296946_chk'
  tag severity: 'medium'
  tag gid: 'V-217026'
  tag rid: 'SV-217026r604135_rule'
  tag stig_id: 'JUNI-RT-000210'
  tag gtitle: 'SRG-NET-000076-RTR-000001'
  tag fix_id: 'F-18253r296947_fix'
  tag 'documentable'
  tag legacy: ['SV-101047', 'V-90837']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
