control 'SV-235753' do
  title 'URLs must be whitelisted for plugin use if used.'
  desc 'Define a list of sites, based on URL patterns that can open pop-up windows.'
  desc 'check', 'This requirement for "Allow pop-up windows on specific sites" is not required; this is optional.

The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Allow pop-up windows on specific sites" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

"PopupsAllowedForUrls" must be set as follows:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\PopupsAllowedForUrls\\1 = mydomain.com
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\PopupsAllowedForUrls\\2 = myagency.mil

If configured, the list of domains for which Microsoft Edge allows pop-ups may be allowlisted.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Allow pop-up windows on specific sites" to "Enabled". A list of allowlisted URLs may be specified here.'
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38972r862951_chk'
  tag severity: 'low'
  tag gid: 'V-235753'
  tag rid: 'SV-235753r862952_rule'
  tag stig_id: 'EDGE-00-000039'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-38935r766856_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
