control 'SV-207545' do
  title 'The print-category variable for the configuration of BIND 9.x server logs must be configured to record information indicating which process generated the events.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident. Associating information about where the event occurred within the application provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured application. In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality.'
  desc 'check', 'For each logging channel that is defined, verify that the "print-category" sub statement is listed.

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
print-category yes;
};
};

If the "print-category" statement is missing, this is a finding.

If the "print-category" statement is not set to "yes", this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "print-category" sub statement to the "channel" statement.

Configure the "print-category" sub statement to "yes"

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7800r283689_chk'
  tag severity: 'low'
  tag gid: 'V-207545'
  tag rid: 'SV-207545r612253_rule'
  tag stig_id: 'BIND-9X-001032'
  tag gtitle: 'SRG-APP-000097-DNS-000008'
  tag fix_id: 'F-7800r283690_fix'
  tag 'documentable'
  tag legacy: ['SV-87013', 'V-72389']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
