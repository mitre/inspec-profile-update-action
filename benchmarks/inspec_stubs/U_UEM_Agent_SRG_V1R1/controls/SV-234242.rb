control 'SV-234242' do
  title 'The UEM Agent must be configured to enable the following function: transfer managed endpoint device audit logs read by the UEM Agent to an UEM server or third-party audit management server.'
  desc 'Audit logs and alerts enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify when the security posture of the device is not as expected. This enables the UEM administrator to take an appropriate remedial action. MD audit logs must be transferred to an audit management service so they can be analyzed and acted on.

'
  desc 'check', 'Verify the UEM Agent has enabled the following function: transfer managed endpoint device audit logs read by the UEM Agent to an UEM server or third-party audit management server.

If the UEM Agent has not enabled the following function: transfer managed endpoint device audit logs read by the UEM Agent to an UEM server or third-party audit management server, this is a finding.'
  desc 'fix', 'Configure the UEM Agent to enable the following function: transfer managed endpoint device audit logs read by the UEM Agent to an UEM server or third-party audit management server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37427r612032_chk'
  tag severity: 'medium'
  tag gid: 'V-234242'
  tag rid: 'SV-234242r617354_rule'
  tag stig_id: 'SRG-APP-000358-UEM-100013'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-37392r612033_fix'
  tag satisfies: ['FMT_SMF_EXT.4.1\nReference: PP-UEM-401006']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
