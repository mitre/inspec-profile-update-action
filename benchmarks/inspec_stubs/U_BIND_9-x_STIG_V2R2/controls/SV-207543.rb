control 'SV-207543' do
  title 'The print-severity variable for the configuration of BIND 9.x server logs must be configured to produce audit records containing information to establish what type of events occurred.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being performed on the system, where an event occurred, when an event occurred, and by whom the event was triggered, in order to compile an accurate risk assessment. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured DNS implementation. Without log records that aid in the establishment of what types of events occurred and when those events occurred, there is no traceability for forensic or analytical purposes, and the cause of events is severely hindered.'
  desc 'check', 'For each logging channel that is defined, verify that the "print-severity" sub statement is listed:

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
print-severity yes;
};
};

If the "print-severity" statement is missing, this is a finding.

If the "print-severity" statement is not set to "yes", this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "print-severity" sub statement to the "channel" statement.

Configure the "print-severity" sub statement to "yes"

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7798r283683_chk'
  tag severity: 'low'
  tag gid: 'V-207543'
  tag rid: 'SV-207543r612253_rule'
  tag stig_id: 'BIND-9X-001030'
  tag gtitle: 'SRG-APP-000095-DNS-000006'
  tag fix_id: 'F-7798r283684_fix'
  tag 'documentable'
  tag legacy: ['SV-87009', 'V-72385']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
