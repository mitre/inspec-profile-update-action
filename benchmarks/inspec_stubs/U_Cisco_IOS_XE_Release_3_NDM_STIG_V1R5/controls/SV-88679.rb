control 'SV-88679' do
  title 'The Cisco IOS XE router must off load audit records via syslog so the audit records can be backed up every seven days.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to use syslog.

The configuration should look similar to the example below:

logging host 1.1.1.1

If syslog is not configured, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to use syslog.

The configuration should look similar to the example below:

logging host 1.1.1.1'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74089r3_chk'
  tag severity: 'low'
  tag gid: 'V-74005'
  tag rid: 'SV-88679r2_rule'
  tag stig_id: 'CISR-ND-000043'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-80545r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
