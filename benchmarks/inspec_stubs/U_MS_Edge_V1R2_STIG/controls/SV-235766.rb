control 'SV-235766' do
  title 'Tracking of browsing activity must be disabled.'
  desc "The setting allows websites to be blocked from tracking users' web-browsing activity.

If this policy is disabled or is not configured, users can set their own level of tracking prevention.

Policy options mapping:
- TrackingPreventionOff (0) = Off (no tracking prevention)
- TrackingPreventionBasic (1) = Basic (blocks harmful trackers; content and ads will be personalized)
- TrackingPreventionBalanced (2) = Balanced (blocks harmful trackers and trackers from sites user has not visited; content and ads will be less personalized)
- TrackingPreventionStrict (3) = Strict (blocks harmful trackers and majority of trackers from all sites; content and ads will have minimal personalization; some parts of sites might not work)"
  desc 'check', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Block tracking of users' web-browsing activity" must be set to "Enabled" with the option value set to "Balanced" or "Strict".

Use the Windows Registry Editor to navigate to the following key:
HKLM\SOFTWARE\Policies\Microsoft\Edge

If the value for "TrackingPrevention" is not set to "REG_DWORD = 2" or "REG_DWORD = 3", this is a finding.)
  desc 'fix', %q(Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Block tracking of users' web-browsing activity" to "Balanced" or "Strict".)
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38985r766872_chk'
  tag severity: 'medium'
  tag gid: 'V-235766'
  tag rid: 'SV-235766r766874_rule'
  tag stig_id: 'EDGE-00-000054'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-38948r766873_fix'
  tag 'documentable'
  tag cci: ['CCI-000388']
  tag nist: ['CM-7 (3)']
end
