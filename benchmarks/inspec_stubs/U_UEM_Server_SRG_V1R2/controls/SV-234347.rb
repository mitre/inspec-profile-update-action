control 'SV-234347' do
  title 'The UEM server must back up audit records at least every seven days onto a log management server.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps ensure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions. 

Satisfies:FAU_STG_EXT.1.1, FMT_SMF.1.1(2) Refinement b'
  desc 'check', 'Verify the UEM server backs up audit records at least every seven days onto a log management server.

If the UEM server does not back up audit records at least every seven days onto a log management server, this is a finding.'
  desc 'fix', 'Configure the UEM server to back up audit records at least every seven days onto a log management server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37532r614051_chk'
  tag severity: 'medium'
  tag gid: 'V-234347'
  tag rid: 'SV-234347r879582_rule'
  tag stig_id: 'SRG-APP-000125-UEM-000074'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-37497r614052_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
