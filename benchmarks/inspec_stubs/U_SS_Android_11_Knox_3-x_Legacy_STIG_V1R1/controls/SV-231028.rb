control 'SV-231028' do
  title 'Samsung Android must be configured to not allow backup of all applications, configuration data to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Verify requirement KNOX-11-006600 (Disallow USB file transfer) has been implemented.

If "Disallow USB file transfer" has not been implemented, this is a finding.'
  desc 'fix', 'Verify "USB file transfer" has been "Disallowed" (see requirement KNOX-11-006600 [Legacy]).'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33958r592698_chk'
  tag severity: 'medium'
  tag gid: 'V-231028'
  tag rid: 'SV-231028r608683_rule'
  tag stig_id: 'KNOX-11-007000'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-33931r592699_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
