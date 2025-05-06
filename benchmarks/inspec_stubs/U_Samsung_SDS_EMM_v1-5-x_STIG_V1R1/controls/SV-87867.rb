control 'SV-87867' do
  title 'The Samsung SDS EMM agent must be configured for the periodicity of reachability events for six hours or less.'
  desc 'Mobile devices that do not enforce security policy or verify the status of the device are vulnerable to a variety of attacks. The key security function of MDM technology is to distribute mobile device security polices in such a manner that they are enforced on managed mobile devices. To accomplish this function, the Samsung SDS EMM agent must verify the status and other key information of the managed device and report that status to the MDM server periodically.

SFR ID: FMT_SMF_EXT.3.2'
  desc 'check', 'Review the MDM agent configuration settings to determine if the agent is configured with a periodicity of reachable events set to six hours or less.

This validation procedure is performed on both the Samsung SDS EMM Server Admin Console. 
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Settings >> Service >> Configuration.
3) For Android: On row 20 verify “Inventory Collection Period for Android (Hrs)” is set to "6" or less.
4) For iOS: On row 21 verify “Inventory Collection Period for iOS (Hrs)” is set to "6" or less.

If the periodicity of reachable events is not set to "6" hours or less, this is a finding.'
  desc 'fix', 'Configure the MDM agent periodicity of reachable events to six hours or less.

On the MDM console, do the following:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Settings >> Service >> Configuration.
3) For Android: Ensure that row 20 “Inventory Collection Period for Android (Hrs)” shows a value of "6" or less.
4) For iOS: Ensure that row 21 “Inventory Collection Period for iOS (Hrs)” shows a value of "6" or less.
5) Click on the check-mark box in the top left of the "Configuration" screen to "Apply Changes".
6) Click “OK” on the “Notify” save completed window.

On the MDM agent, do the following:
No actions required on the MDM agent'
  impact 0.3
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73317r1_chk'
  tag severity: 'low'
  tag gid: 'V-73215'
  tag rid: 'SV-87867r1_rule'
  tag stig_id: 'SEMM-15-200010'
  tag gtitle: 'PP-MDM-201101'
  tag fix_id: 'F-79661r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
