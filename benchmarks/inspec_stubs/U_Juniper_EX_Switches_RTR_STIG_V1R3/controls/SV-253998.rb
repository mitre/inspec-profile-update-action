control 'SV-253998' do
  title 'The Juniper router must be configured to log all packets that have been dropped.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being done or attempted to be done, and by whom, to compile an accurate risk assessment. Auditing the actions on network devices provides a means to recreate an attack or identify a configuration mistake on the device.'
  desc 'check', 'Review the router interface firewall filters to verify all deny statements are logged. At a minimum, all discarding filter terms must have the "syslog" action enabled.

Verify all discarding firewall filter terms are configured with (minimally) the "syslog" action:
[edit firewall]
family inet {
    filter <filter name> {
        term <name> {
            from {
                <match conditions>;
            }
            then {
                log;
                syslog; <<< Must be enabled for local and external syslog.
                discard;
            }
        }
    }
}
family inet6 {
    filter <filter name> {
        term <name> {
            from {
                <match conditions>;
            }
            then {
                log;
                syslog; <<< Must be enabled for local and external syslog.
                discard;
            }
        }
    }
}

If packets being dropped are not logged, this is a finding.'
  desc 'fix', 'Configure interface firewall filters to log all deny statements.

All discarding firewall filter terms:
<filter terms and match conditions>
set firewall family inet filter <filter name> term <name> then log
set firewall family inet filter <filter name> term <name> then syslog <<< Minimally must be configured for all discarding filter terms.
set firewall family inet filter <filter name> term <name> then discard

<filter terms and match conditions>
set firewall family inet6 filter <filter name> term <name> then log
set firewall family inet6 filter <filter name> term <name> then syslog <<< Minimally must be configured for all discarding filter terms.
set firewall family inet6 filter <filter name> term <name> then discard'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57450r844025_chk'
  tag severity: 'low'
  tag gid: 'V-253998'
  tag rid: 'SV-253998r844027_rule'
  tag stig_id: 'JUEX-RT-000260'
  tag gtitle: 'SRG-NET-000078-RTR-000001'
  tag fix_id: 'F-57401r844026_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
