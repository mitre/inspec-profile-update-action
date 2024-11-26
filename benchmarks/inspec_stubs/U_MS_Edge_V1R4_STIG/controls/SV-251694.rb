control 'SV-251694' do
  title 'The list of domains media autoplay allows must be allowlisted.'
  desc "Define a list of sites, based on URL patterns, that are allowed to autoplay media.

If this policy is not configured, the global default value from the AutoplayAllowed policy (if set) or the user's personal configuration is used for all sites.

EDGE-00-000024 disables the AutoplayAllowed policy."
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow media autoplay on specific sites" may be set to "allow" for allowlisted domains.

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

AutoplayAllowlist may be set as follows:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\AutoplayAllowlist\\1 = mydomain.com
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\AutoplayAllowlist\\2 = myagency.mil

This requirement for "AutoplayAllowlist" is not required; this is optional.

If configured, the list of domains for which autoplay is allowed must be allowlisted; otherwise, this is a finding.

If this machine is on SIPRNet, this is Not Applicable.'
  desc 'fix', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow media autoplay on specific sites" may be set to "allow" for allowlisted domains.'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-55131r808526_chk'
  tag severity: 'medium'
  tag gid: 'V-251694'
  tag rid: 'SV-251694r808528_rule'
  tag stig_id: 'EDGE-00-000064'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-55085r808527_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
