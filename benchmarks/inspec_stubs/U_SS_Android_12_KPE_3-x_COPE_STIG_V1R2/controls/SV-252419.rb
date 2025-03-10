control 'SV-252419' do
  title "Samsung Android must be configured to not allow backup of all applications' configuration data to locally connected systems."
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Verify requirement KNOX-12-210130 (Disallow USB file transfer) has been implemented.

If "Disallow USB file transfer" has not been implemented, this is a finding.'
  desc 'fix', 'Verify "USB file transfer" has been "Disallowed" (see requirement KNOX-12-210130).'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COPE'
  tag check_id: 'C-55875r815468_chk'
  tag severity: 'medium'
  tag gid: 'V-252419'
  tag rid: 'SV-252419r816526_rule'
  tag stig_id: 'KNOX-12-210140'
  tag gtitle: 'PP-MDF-323240'
  tag fix_id: 'F-55825r815469_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
