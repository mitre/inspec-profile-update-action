control 'SV-234245' do
  title 'The UEM Agent must record the reference identifier of the UEM Server during the enrollment process.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For audit logs to be useful, administrators must have the ability to view them.

'
  desc 'check', 'Verify the UEM Agent records the reference identifier of the UEM Server during the enrollment process.

If the UEM Agent does not record the reference identifier of the UEM Server during the enrollment process, this is a finding.'
  desc 'fix', 'Configure the UEM Agent to record the reference identifier of the UEM Server during the enrollment process.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37430r612041_chk'
  tag severity: 'medium'
  tag gid: 'V-234245'
  tag rid: 'SV-234245r617354_rule'
  tag stig_id: 'SRG-APP-000516-UEM-100006'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37395r612042_fix'
  tag satisfies: ['FIA_ENR_EXT.2.1']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
