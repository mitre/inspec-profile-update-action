control 'SV-217027' do
  title 'The Juniper router must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.'
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

If the router is not configured to produce audit records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the router to log events containing information to establish where the events occurred as shown in the example below.
 
[edit system syslog]
set file LOG_FILE any any'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18256r296949_chk'
  tag severity: 'medium'
  tag gid: 'V-217027'
  tag rid: 'SV-217027r639663_rule'
  tag stig_id: 'JUNI-RT-000220'
  tag gtitle: 'SRG-NET-000077-RTR-000001'
  tag fix_id: 'F-18254r296950_fix'
  tag 'documentable'
  tag legacy: ['SV-101049', 'V-90839']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
