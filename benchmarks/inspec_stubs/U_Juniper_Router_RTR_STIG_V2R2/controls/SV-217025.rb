control 'SV-217025' do
  title 'The Juniper router must be configured to log all packets that have been dropped.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being done or attempted to be done, and by whom, to compile an accurate risk assessment. Auditing the actions on network devices provides a means to recreate an attack or identify a configuration mistake on the device.'
  desc 'check', 'Review all filters to verify that packets that are discarded or rejected are logged as shown in the configuration below.

firewall {
    family inet {
        filter XYZ
            …
            …
            …
            }
            term DENY_BY_DEFAULT {
                then {
                    syslog;
                    discard;
                }
            }
        }
    }

Verify that logging is enabled to capture packets that are dropped as shown in the configuration below.

system {
    host-name XYZ;
    …
    …
    …
    }
    syslog {
        file LOG_FILE {
            firewall any;
        }
    }
}

Note: The “any” parameter can be configured in lieu of the “firewall” parameter.

If packets being dropped are not logged, this is a finding.'
  desc 'fix', 'Configure the firewall terms that discards or rejects packets to log the action as shown in the example below.

[edit firewall family inet]
set filter FILTER_INBOUND term DENY_BY_DEFAULT then syslog discard

Configure logging to record packets being dropped by firewall filters as shown in the example below.

[edit system syslog]
set file LOG_FILE firewall any

Note: The “any” parameter can be configured in lieu of the “firewall” parameter.'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18254r296943_chk'
  tag severity: 'low'
  tag gid: 'V-217025'
  tag rid: 'SV-217025r639663_rule'
  tag stig_id: 'JUNI-RT-000200'
  tag gtitle: 'SRG-NET-000078-RTR-000001'
  tag fix_id: 'F-18252r296944_fix'
  tag 'documentable'
  tag legacy: ['SV-101045', 'V-90835']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
