control 'SV-214519' do
  title 'The Juniper SRX Services Gateway must generate log records when firewall filters, security screens and security policies are invoked and the traffic is denied or restricted.'
  desc 'Without generating log records that log usage of objects by subjects and other objects, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Security objects are data objects which are controlled by security policy and bound to security attributes.

By default, the Juniper SRX will not forward traffic unless it is explicitly permitted via security policy. Logging for Firewall security-related sources such as screens and security policies must be configured separately. To ensure firewall filters, security screens and security policies send events to a Syslog server and local logs, security logging must be configured one each firewall term.'
  desc 'check', 'To verify what is logged in the Syslog, view the Syslog server (Syslog server configuration is out of scope for this STIG); however, the reviewer must also verify that packets are being logged to the local log using the following commands.

From operational mode, enter the following command.

show firewall log

View the Action column; the configured action of the term matches the action taken on the packet: A (accept), D (discard).

If events in the log do not reflect the action taken on the packet, this is a finding.'
  desc 'fix', 'Include the log and/or syslog action in all term to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Firewall filter:
[edit]
set firewall family <family name> filter <filter_name> term <term_name> then log

Examples: 
set firewall family inet filter protect_re term tcp-connection then syslog
set firewall family inet filter protect_re term tcp-connection then log
set firewall family inet filter ingress-filter-v4 term deny-dscp then log
set firewall family inet filter ingress-filter-v4 term deny-dscp then syslog

Security policy and security screens:
set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway ALG'
  tag check_id: 'C-15725r297241_chk'
  tag severity: 'medium'
  tag gid: 'V-214519'
  tag rid: 'SV-214519r557389_rule'
  tag stig_id: 'JUSX-AG-000036'
  tag gtitle: 'SRG-NET-000492-ALG-000027'
  tag fix_id: 'F-15723r297242_fix'
  tag 'documentable'
  tag legacy: ['V-66303', 'SV-80793']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
