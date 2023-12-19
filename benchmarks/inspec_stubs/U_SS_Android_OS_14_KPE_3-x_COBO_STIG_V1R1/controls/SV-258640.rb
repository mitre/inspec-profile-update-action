control 'SV-258640' do
  title 'Samsung Android must be configured to not allow backup of all applications and configuration data to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Verify requirement KNOX-14-110140 (disallow USB file transfer) has been implemented.

If disallow USB file transfer has not been implemented, this is a finding.'
  desc 'fix', 'Ensure USB file transfer has been disallowed (refer to requirement KNOX-14-110140).'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62380r931118_chk'
  tag severity: 'medium'
  tag gid: 'V-258640'
  tag rid: 'SV-258640r931120_rule'
  tag stig_id: 'KNOX-14-110150'
  tag gtitle: 'PP-MDF-333240'
  tag fix_id: 'F-62289r931119_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
