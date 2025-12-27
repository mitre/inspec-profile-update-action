control 'SV-235749' do
  title 'Site tracking of a user’s location must be disabled.'
  desc %q(Set whether websites can track users' physical locations. Tracking can be allowed by default ("AllowGeolocation") or denied by default ("BlockGeolocation"), or the user can be asked each time a website requests their location ("AskGeolocation").

If this policy is not configured, "AskGeolocation" is used and the user can change it.

Policy options mapping:
- AllowGeolocation (1) = Allow sites to track users' physical location.
- BlockGeolocation (2) = Do not allow any site to track users' physical location.
- AskGeolocation (3) = Ask whenever a site wants to track users' physical location.)
  desc 'check', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Default geolocation setting" must be set to "enabled" with the option value set to "Don't allow any site to track users' physical location".

Use the Windows Registry Editor to navigate to the following key:
HKLM\SOFTWARE\Policies\Microsoft\Edge

If the value for "DefaultGeolocationSetting" is not set to "REG_DWORD = 2", this is a finding.)
  desc 'fix', %q(Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Default geolocation setting" to "enabled" and select "Don't allow any site to track users' physical location".)
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38968r626443_chk'
  tag severity: 'medium'
  tag gid: 'V-235749'
  tag rid: 'SV-235749r626523_rule'
  tag stig_id: 'EDGE-00-000032'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38931r626444_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
