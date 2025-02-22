control 'SV-207544' do
  title 'The print-time variable for the configuration of BIND 9.x server logs must be configured to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident. 

Associating event types with detected events in the application and audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured application. In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time).'
  desc 'check', 'For each logging channel that is defined, verify that the "print-time" sub statement is listed.

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
print-time yes;
};
};

If the "print-time" statement is missing, this is a finding.

If the "print-time" statement is not set to "yes", this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "print-time" sub statement to the "channel" statement.

Configure the "print-time" sub statement to "yes"

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7799r283686_chk'
  tag severity: 'low'
  tag gid: 'V-207544'
  tag rid: 'SV-207544r612253_rule'
  tag stig_id: 'BIND-9X-001031'
  tag gtitle: 'SRG-APP-000096-DNS-000007'
  tag fix_id: 'F-7799r283687_fix'
  tag 'documentable'
  tag legacy: ['SV-87011', 'V-72387']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
