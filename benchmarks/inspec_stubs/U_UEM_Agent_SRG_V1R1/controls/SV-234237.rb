control 'SV-234237' do
  title 'The UEM Agent must be configured to enable the following function: read audit logs of the managed endpoint device.'
  desc 'Audit logs and alerts enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify when the security posture of the device is not as expected. This enables the UEM administrator to take an appropriate remedial action.

'
  desc 'check', 'Verify the UEM Agent has enabled the following function: read audit logs of the managed endpoint device.

If the UEM Agent has not enabled the following function: read audit logs of the managed endpoint device, this is a finding.'
  desc 'fix', 'Configure the UEM Agent to enable the following function: read audit logs of the managed endpoint device.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37422r612017_chk'
  tag severity: 'medium'
  tag gid: 'V-234237'
  tag rid: 'SV-234237r617354_rule'
  tag stig_id: 'SRG-APP-000089-UEM-100012'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-37387r612018_fix'
  tag satisfies: ['FMT_SMF_EXT.4.1\nReference: PP-UEM-401005']
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
