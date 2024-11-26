control 'SV-235769' do
  title 'User feedback must be disabled.'
  desc 'Microsoft Edge uses the Edge Feedback feature (enabled by default) to allow users to send feedback, suggestions, or customer surveys and to report any issues with the browser. By default, users cannot disable (turn off) the Edge Feedback feature.

If this policy is enabled or not configured, users can invoke Edge Feedback.

If this policy is disabled, users cannot invoke Edge Feedback.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow user feedback" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for UserFeedbackAllowed is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow user feedback" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38988r626503_chk'
  tag severity: 'medium'
  tag gid: 'V-235769'
  tag rid: 'SV-235769r626523_rule'
  tag stig_id: 'EDGE-00-000057'
  tag gtitle: 'SRG-APP-000152'
  tag fix_id: 'F-38951r626504_fix'
  tag 'documentable'
  tag cci: ['CCI-000392']
  tag nist: ['CM-8 a 2']
end
