control 'SV-253996' do
  title 'The Juniper router must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as router components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured router.'
  desc 'check', %q(The router must log all packets that have been dropped via the stateless firewall filter. Verify all discarding firewall filter terms are configured to send events to syslog.
Note: Stateless firewall filters support "log" and "syslog" actions. The "log" action maintains a temporary list of events and the "syslog" action generates events for local storage and/or external syslog servers. Verify at least "syslog" is associated with all discarding terms.

For example:
[edit firewall]
family inet {
    filter <filter name> {
        term 1 {
            from {
                <match conditions>;
            }
            then {
                log;
                syslog; <<< At a minimum, the 'syslog' action must be enabled for all discarding terms.
                discard;
            }
        }
    }
}
family inet6 {
    filter <filter name> {
        term 1 {
            from {
                <match conditions>;
            }
            then {
                log;
                syslog; <<< At a minimum, the 'syslog' action must be enabled for all discarding terms.
                discard;
            }
        }
    }
}

If the router fails to log all packets that have been dropped via the firewall filter, this is a finding.

Verify logging is enabled for local and/or external syslog. To meet this requirement, either the "any" or the "firewall" logging facility must be enabled.
Note: To reduce log sizes and to segregate entries, a separate log file for firewall entries is permissible.

[edit system syslog]
host <external syslog address> {
    any info;
    log-prefix <hostname>;
    explicit-priority;
}
file messages {
    any info;
}
time-format year;

Log output must contain an interface name identifying where the packet was filtered.
Note: Logged firewall events include the interface and cannot be configured otherwise. There is no provision for changing the log message or for removing the interface name.

If the logged output does not contain an interface name identifying where the packet was filtered, this is a finding.)
  desc 'fix', 'Configure the router to record the interface in the log record for packets being dropped.

Example firewall filter with logging enabled:
set firewall family inet filter <filter name> term 1 from <match conditions>
set firewall family inet filter <filter name> term 1 then log
set firewall family inet filter <filter name> term 1 then syslog <<< Must be enabled for all discarding terms
set firewall family inet filter <filter name> term 1 then discard
set firewall family inet6 filter <filter name> term 1 from <match conditions>
set firewall family inet6 filter <filter name> term 1 then log
set firewall family inet6 filter <filter name> term 1 then syslog <<< Must be enabled for all discarding terms
set firewall family inet6 filter <filter name> term 1 then discard

Example consolidated logging:
set syslog host <external syslog address> any info
set system syslog file messages any info'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57448r844019_chk'
  tag severity: 'medium'
  tag gid: 'V-253996'
  tag rid: 'SV-253996r844021_rule'
  tag stig_id: 'JUEX-RT-000240'
  tag gtitle: 'SRG-NET-000076-RTR-000001'
  tag fix_id: 'F-57399r844020_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
