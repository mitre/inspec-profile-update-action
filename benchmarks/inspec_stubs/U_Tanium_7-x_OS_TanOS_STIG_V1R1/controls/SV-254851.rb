control 'SV-254851' do
  title 'The Tanium Operating System (TanOS) must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition that occurs when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', '1. Sign in to the TanOS console as a user with the tanadmin role.

2. Enter "A" to go to the "Appliance Configuration" menu.

3. Enter "A" to go to the "Security" menu.

4. Enter "X" to go to the "Advanced Security" menu.

5. If you see "DOS protection: disabled" in the middle of the screen, this is a finding.'
  desc 'fix', '1. Sign in to the TanOS console as a user with the tanadmin role.

2. Enter "A" to go to the "Appliance Configuration" menu.

3. Enter "A" to go to the "Security" menu.

4. Enter " to go to the "Advanced Security" menu.

5. Enter "6" to enable DoS protection. The screen updates with an enabled status.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58464r866092_chk'
  tag severity: 'medium'
  tag gid: 'V-254851'
  tag rid: 'SV-254851r866094_rule'
  tag stig_id: 'TANS-OS-000455'
  tag gtitle: 'SRG-OS-000142'
  tag fix_id: 'F-58408r866093_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
