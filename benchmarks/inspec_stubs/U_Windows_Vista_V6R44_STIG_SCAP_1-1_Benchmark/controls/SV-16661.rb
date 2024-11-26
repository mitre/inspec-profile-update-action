control 'SV-16661' do
  title 'Media DRM – Internet Access'
  desc 'This check verifies that Windows Media Digital Rights Management will be prevented from accessing the internet.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Digital Rights Management “Prevent Windows Media DRM Internet Access” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15722'
  tag rid: 'SV-16661r1_rule'
  tag gtitle: 'Media DRM – Internet Access'
  tag fix_id: 'F-15614r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
