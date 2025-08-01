control 'SV-253997' do
  title 'The Juniper router must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

To compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.'
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

Log output must contain the source IP address and port of the filtered packets.
Note: Logged firewall events include the source, and destination, addresses and cannot be configured otherwise. There is no provision for changing the log message or for removing the source or destination address. 

If the logged output does not contain source IP address and port of the filtered packets, this is a finding.)
  desc 'fix', 'Configure the router to record the source address in the log record for packets being dropped.

Example firewall filter with logging enabled:
set firewall family inet filter <filter name> term 1 from <match conditions>
set firewall family inet filter <filter name> term 1 then log
set firewall family inet filter <filter name> term 1 then syslog <<< Must be enabled for all discarding terms
set firewall family inet filter <filter name> term 1 then discard
set firewall family inet6 filter <filter name> term 1 from <match conditions>
set firewall family inet6 filter <filter name> term 1 then log
set firewall family inet6 filter <filter name> term 1 then syslog <<< Must be enabled for all discarding terms
set firewall family inet6 filter <filter name> term 1 then discard

set syslog host <external syslog address> any info
set system syslog file messages any info'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57449r844022_chk'
  tag severity: 'medium'
  tag gid: 'V-253997'
  tag rid: 'SV-253997r844024_rule'
  tag stig_id: 'JUEX-RT-000250'
  tag gtitle: 'SRG-NET-000077-RTR-000001'
  tag fix_id: 'F-57400r844023_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
