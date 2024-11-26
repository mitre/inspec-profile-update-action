control 'SV-221588' do
  title 'Download restrictions must be configured.'
  desc %q(Configure the type of downloads that Google Chrome will completely block, without letting users override the security decision. If you set this policy, Google Chrome will prevent certain types of downloads, and will not let user bypass the security warnings. When the "Block dangerous downloads" option is chosen, all downloads are allowed, except for those that carry SafeBrowsing warnings. When the "Block potentially dangerous downloads" option is chosen, all downloads allowed, except for those that carry SafeBrowsing warnings of potentially dangerous downloads. When the "Block all downloads" option is chosen, all downloads are blocked.  When this policy is not set, (or the "No special restrictions" option is chosen), the downloads will go through the usual security restrictions based on SafeBrowsing analysis results.

Note that these restrictions apply to downloads triggered from web page content, as well as the 'download link...' context menu option. These restrictions do not apply to the save / download of the currently displayed page, nor does it apply to saving as PDF from the printing options. See https://developers.google.com/safe-browsing for more info on SafeBrowsing. 
0 = No special restrictions
1 = Block dangerous downloads
2 = Block potentially dangerous downloads
3 = Block all downloads)
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.
Universal method:
1. In the omnibox (address bar) type chrome:// policy
2. If "DownloadRestrictions" is not displayed under the "Policy Name" column or it is not set to "1" or "2" under the "Policy Value" column, then this is a finding.

Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the "DownloadRestrictions" value name does not exist or its value data is not set to "1" or "2", then this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.
Windows group policy:
1. Open the group policy editor tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Allow download restrictions
Policy State: 1 or 2
Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23303r415891_chk'
  tag severity: 'medium'
  tag gid: 'V-221588'
  tag rid: 'SV-221588r615937_rule'
  tag stig_id: 'DTBC-0055'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-23292r415892_fix'
  tag 'documentable'
  tag legacy: ['SV-94635', 'V-79931']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
