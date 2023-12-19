control 'SV-245539' do
  title 'Session only based cookies must be disabled.'
  desc "Cookies set by pages matching these URL patterns will be limited to the current session, i.e. they will be deleted when the browser exits.

For URLs not covered by the patterns specified here, or for all URLs if this policy is not set, the global default value will be used either from the 'DefaultCookiesSetting' policy, if it is set, or the user's personal configuration otherwise."
  desc 'check', 'Universal method: 
1. In the omnibox (address bar) type chrome://policy.
2. If the policy "CookiesSessionOnlyForUrls" exists and has any defined values, this is a finding.

Windows method:
1. Start regedit.
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\CookiesSessionOnlyForUrls.
3. If this key exists and has any defined values, this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc 
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Content Settings.
- Policy Name: Limit cookies from matching URLs to the current session
- Policy State: Disabled
- Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23298r754760_chk'
  tag severity: 'medium'
  tag gid: 'V-245539'
  tag rid: 'SV-245539r769360_rule'
  tag stig_id: 'DTBC-0045'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-23287r769362_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
