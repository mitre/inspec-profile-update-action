control 'SV-88677' do
  title 'The Cisco IOS XE router must use internal system clocks to generate time stamps for audit records.'
  desc "In order to determine what is happening within the network infrastructure or to resolve and trace an attack, the network device must support the organization's capability to correlate the audit log data from multiple network devices to acquire a clear understanding of events. In order to correlate auditable events, time stamps are needed on all of the log records.

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose.  (Note that the internal clock is required to be synchronized with authoritative time sources by other requirements.)"
  desc 'check', 'Verify that the Cisco IOS XE router is configured to use internal system clocks to generate time stamps for audit records.

The configuration should look similar to the example below:

service timestamps log datetime

If internal systems clocks are not being used, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to use internal clocks to generate time stamps for audit records.

The configuration should look similar to the example below:

service timestamps log datetime'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74087r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74003'
  tag rid: 'SV-88677r2_rule'
  tag stig_id: 'CISR-ND-000036'
  tag gtitle: 'SRG-APP-000116-NDM-000234'
  tag fix_id: 'F-80543r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
