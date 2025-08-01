control 'SV-221596' do
  title 'URLs must be allowlisted for Autoplay use.'
  desc 'Controls the allowlist of URL patterns that autoplay will always be enabled on. If the "AutoplayAllowed" policy is set to "True" then this policy will have no effect. If the "AutoplayAllowed" policy is set to "False", then any URL patterns set in this policy will still be allowed to play.'
  desc 'check', 'Universal method:
1. In the omnibox (address bar), type chrome://policy.
2. If “AutoplayAllowlist” under the “Policy Name” column may be set to a list of administrator-approved URLs under the “Policy Value” column. This requirement is optional.

Windows method:
1. Start regedit.
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the “AutoplayAllowlist” key may contain a list of administrator-approved URLs. This requirement is optional.'
  desc 'fix', 'Windows group policy:
1. Open the “group policy editor” tool with gpedit.msc.
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome
- Policy Name: Allow media autoplay on a allowlist of URL patterns.
- Policy State: Enabled
- Policy Value 1: [*.]mil
- Policy Value 2: [*.]gov

Note: Policy values are examples.'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23311r820740_chk'
  tag severity: 'medium'
  tag gid: 'V-221596'
  tag rid: 'SV-221596r820742_rule'
  tag stig_id: 'DTBC-0065'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-23300r820741_fix'
  tag 'documentable'
  tag legacy: ['SV-96303', 'V-81589']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
