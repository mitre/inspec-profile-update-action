control 'SV-258676' do
  title 'Samsung Android must be configured to not allow backup of all applications and configuration data to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Verify requirement KNOX-14-210140 (disallow USB file transfer) has been implemented.

If "Disallow USB file transfer" has not been implemented, this is a finding.'
  desc 'fix', 'Ensure "USB file transfer" has been disallowed (refer to requirement KNOX-14-210140).'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62416r931226_chk'
  tag severity: 'medium'
  tag gid: 'V-258676'
  tag rid: 'SV-258676r931228_rule'
  tag stig_id: 'KNOX-14-210150'
  tag gtitle: 'PP-MDF-333240'
  tag fix_id: 'F-62325r931227_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
