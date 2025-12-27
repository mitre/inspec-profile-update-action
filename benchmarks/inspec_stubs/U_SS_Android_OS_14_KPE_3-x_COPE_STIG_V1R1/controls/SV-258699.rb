control 'SV-258699' do
  title 'The Samsung Android device must be configured to disable the use of third-party keyboards.'
  desc 'Many third-party keyboard applications are known to contain malware.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the managed Samsung Android 14 configuration settings to confirm that no third-party keyboards are enabled.
 
This procedure is performed on the management tool.
 
On the management tool:
1. Open "Input methods".
2. Tap "Set input methods".
3. Verify only the approved keyboards are selected.

If third-party keyboards are allowed, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 14 device to disallow the use of third-party keyboards. 
 
On the management tool:
1. Open "Input methods".
2. Tap "Set input methods".
3. Select only the approved keyboard.

Additionally, Administrators can configure application allowlists for Google Play that do not have any third-party keyboards for user installation.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62439r931295_chk'
  tag severity: 'low'
  tag gid: 'V-258699'
  tag rid: 'SV-258699r931297_rule'
  tag stig_id: 'KNOX-14-225070'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62348r931296_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
