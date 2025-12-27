control 'SV-251806' do
  title 'Samsung Android must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Verify requirement KNOX-12-110030 (minimum password quality) has been implemented.

If a "minimum password quality" has not been implemented, this is a finding.'
  desc 'fix', 'Implement a "minimum password quality" (see requirement KNOX-12-110030).'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55266r814172_chk'
  tag severity: 'medium'
  tag gid: 'V-251806'
  tag rid: 'SV-251806r814174_rule'
  tag stig_id: 'KNOX-12-110040'
  tag gtitle: 'PP-MDF-323020'
  tag fix_id: 'F-55220r814173_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
