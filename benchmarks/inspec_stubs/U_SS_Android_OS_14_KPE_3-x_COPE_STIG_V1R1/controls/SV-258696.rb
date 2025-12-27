control 'SV-258696' do
  title 'The Samsung Android device must be provisioned as a fully managed device and configured to create a work profile.'
  desc 'The Android Enterprise work profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify requirement KNOX-14-210010 (COPE enrollment) has been implemented.

If "COPE enrollment" has not been implemented, this is a finding."'
  desc 'fix', 'Implement "COPE enrollment" (refer to requirement KNOX-14-210010).'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62436r931286_chk'
  tag severity: 'medium'
  tag gid: 'V-258696'
  tag rid: 'SV-258696r931288_rule'
  tag stig_id: 'KNOX-14-225040'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62345r931287_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
