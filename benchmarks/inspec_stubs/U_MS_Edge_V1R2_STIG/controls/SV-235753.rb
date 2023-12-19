control 'SV-235753' do
  title 'URLs must be whitelisted for plugin use.'
  desc 'Define a list of sites, based on URL patterns that can open pop-up windows.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Allow pop-up windows on specific sites" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

"PopupsAllowedForUrls" must be set as follows:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\PopupsAllowedForUrls\\1 = mydomain.com
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\PopupsAllowedForUrls\\2 = myagency.mil

This requirement for "Allow pop-up windows on specific sites" is not required; this is optional.

If configured, the list of domains for which Microsoft Edge allows pop-ups must be allowlisted; otherwise this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Allow pop-up windows on specific sites" to "Enabled". A list of allowlisted URLs may be specified here.'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38972r766855_chk'
  tag severity: 'medium'
  tag gid: 'V-235753'
  tag rid: 'SV-235753r766857_rule'
  tag stig_id: 'EDGE-00-000039'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-38935r766856_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
