control 'SV-80867' do
  title 'The Juniper Networks SRX Series Gateway IDPS must provide audit record generation capability for detecting events based on implementation of policy filters, rules, and signatures.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The Juniper SRX with IDP-enabled policies has the capability to capture and log detected security violations and potential security violations.'
  desc 'check', 'To verify that the configuration is working properly, use the following command:

[edit]
show security alarms 

View the configured alarms to verify at least one option for potential-violation is set to “idp”.

If a potential-violation alarm is not defined for “idp”, this is a finding.'
  desc 'fix', 'A Routing Engine configuration option allows the enabling and disabling of IDP alarms.

By default, the IDP attack event triggers the current logs without raising any alarms. When the option is set and the system is configured appropriately, the IDP logs on the Packet Forwarding Engine will be forwarded to Routing Engine, which then parses the IDP attack logs and raises IDP alarms as necessary.

To enable an IDP alarm, use the set security alarms potential-violation idp command.

To turn on logging, you must first turn on notification to log attacks:
set security idp idp-policy recommended rulebase-ips rule-1 then notification log-attacks

Configure Syslog (adding to the firewall stanza).
syslog {
 file IDP_Log {
 any any;
 match RT_IDP;'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67021r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66377'
  tag rid: 'SV-80867r1_rule'
  tag stig_id: 'JUSX-IP-000001'
  tag gtitle: 'SRG-NET-000113-IDPS-00013'
  tag fix_id: 'F-72453r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
