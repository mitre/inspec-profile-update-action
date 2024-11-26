control 'SV-88751' do
  title 'The Cisco IOS XE router must generate audit log events for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Review the router configuration to determine if it is in compliance with this requirement. The configuration should look similar to the example below.

logging buffered nnnn informational
logging console informational
logging trap warning
logging host x.x.x.x

Note: Severity levels can be set to operational requirements. Informational is the default severity level; hence, if the severity level is configured to informational, the “logging trap” command will not be shown in the configuration.

If the router is not configured to generate audit log events for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Configure the router to send logs to the console, buffer, and syslog server as shown in the example below.

logging buffered nnnn informational
logging console informational
logging trap warning
logging host x.x.x.x

Note: Severity levels can be set to operational requirements.'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74169r7_chk'
  tag severity: 'medium'
  tag gid: 'V-74077'
  tag rid: 'SV-88751r3_rule'
  tag stig_id: 'CISR-ND-000132'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-80617r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
