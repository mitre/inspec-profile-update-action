control 'SV-80877' do
  title 'The Juniper Networks SRX Series Gateway IDPS must provide audit record generation with a configurable severity and escalation level capability.'
  desc 'Without the capability to generate audit records with a severity code it is difficult to track and handle detection events.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The IDPS must have the capability to collect and log the severity associated with the policy, rule, or signature. IDPS products often have either pre-configured and/or a configurable method for associating an impact indicator or severity code with signatures and rules, at a minimum.'
  desc 'check', 'Use the following command to view the IDP rules:

[edit]
show security idp status

The IDP traffic log can also be inspected to verify that IDP detection events contain a severity level in the log record.

If active IDP rules exist that do not include a severity level, this is a finding.'
  desc 'fix', 'Example configuration to set the severity level on the IDP rules:

Define an attack as match criteria.
[edit security idp idp-policy base-policy rulebase-ips rule R1]
set match attacks predefined-attack-groups "TELNET-Critical"

Specify an action for the rule.
[edit security idp idp-policy base-policy rulebase-ips rule R1]
set then action drop-connection

Specify notification and logging options for the rule.
[edit security idp idp-policy base-policy rulebase-ips rule R1]
set then notification log-attacks alert

Set the severity level for the rule.

[edit security idp idp-policy base-policy rulebase-ips rule R1] 

set then severity critical'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67033r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66387'
  tag rid: 'SV-80877r1_rule'
  tag stig_id: 'JUSX-IP-000004'
  tag gtitle: 'SRG-NET-000113-IDPS-00189'
  tag fix_id: 'F-72463r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
