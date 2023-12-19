control 'SV-235728' do
  title 'Network prediction must be disabled.'
  desc 'Enables network prediction and prevents users from changing this setting.

This controls DNS prefetching, TCP and SSL pre-connection, and pre-rendering of web pages.

If this policy is not configured, network prediction is enabled but the user can change it.

Policy options mapping:
- NetworkPredictionAlways (0) = Predict network actions on any network connection.
- NetworkPredictionWifiOnly (1) = Not supported; if this value is used it will be treated as if "Predict network actions on any network connection" (0) was set.
- NetworkPredictionNever (2) = Do not predict network actions on any network connection.'
  desc 'check', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable network prediction" must be set to "Enabled" with the option value set to "Don't predict network actions on any network connection".

Use the Windows Registry Editor to navigate to the following key:
HKLM\SOFTWARE\Policies\Microsoft\Edge\Recommended

If the value for NetworkPredictionOptions is not set to "REG_DWORD = 2", this is a finding.)
  desc 'fix', %q(Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable network prediction" to "Enabled" with the option value set to "Don't predict network actions on any network connection".)
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38947r626380_chk'
  tag severity: 'medium'
  tag gid: 'V-235728'
  tag rid: 'SV-235728r626523_rule'
  tag stig_id: 'EDGE-00-000011'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38910r626381_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
