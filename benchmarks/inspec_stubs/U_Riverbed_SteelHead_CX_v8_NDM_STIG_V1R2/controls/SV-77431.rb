control 'SV-77431' do
  title 'Riverbed Optimization System (RiOS) must enable the password authentication control policy to ensure password complexity controls and other password policy requirements are enforced.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'Verify authentication policy is enabled.

Navigate to the device Management Console
Navigate to:
Configure >> Security >> Password Policy

Verify the "Enable Account Control" is selected

If "Enable Account Control" is not set, this is a finding.'
  desc 'fix', 'Enable RiOS authentication policy.

Navigate to the device Management Console, then
Navigate to:
Configure >> Security >> Password Policy
Select "Enable Account Control"

Set values for the user account

Click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62941'
  tag rid: 'SV-77431r1_rule'
  tag stig_id: 'RICX-DM-000091'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-68859r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
