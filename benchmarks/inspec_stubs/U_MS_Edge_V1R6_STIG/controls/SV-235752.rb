control 'SV-235752' do
  title 'Download restrictions must be configured.'
  desc %q(Configure the type of downloads that Microsoft Edge completely blocks, without letting users override the security decision.

Set "BlockDangerousDownloads" to allow all downloads except for those that carry Microsoft Defender SmartScreen warnings.

Set "BlockPotentiallyDangerousDownloads" to allow all downloads except for those that carry Microsoft Defender SmartScreen warnings of potentially dangerous or unwanted downloads.

Set "BlockAllDownloads" to block all downloads.

If this policy is not configured or the 'DefaultDownloadSecurity' option set, downloads go through the usual security restrictions based on Microsoft Defender SmartScreen analysis results.

Note that these restrictions apply to downloads from web page content, as well as the "download link..." context menu option. These restrictions do not apply to saving or downloading the currently displayed page, nor do they apply to the "Save as PDF" option from the printing options.

See https://go.microsoft.com/fwlink/?linkid=2094934 for more information on Microsoft Defender SmartScreen.

Policy options mapping:
- DefaultDownloadSecurity (0) = No special restrictions.
- BlockDangerousDownloads (1) = Block malicious downloads and dangerous file types.
- BlockPotentiallyDangerousDownloads (2) = Block potentially dangerous or unwanted downloads and dangerous file types.
- BlockAllDownloads (3) = Block all downloads.
- BlockMaliciousDownloads (4) = Block malicious downloads.)
  desc 'check', 'If this machine is on SIPRNet, this is Not Applicable.

The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow download restrictions" must be set to "Enabled" with the option value set to "BlockDangerousDownloads" or "Block potentially dangerous or unwanted downloads". The more restrictive option, "Block all downloads" is also acceptable.

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "DownloadRestrictions" is set to "REG_DWORD = 0", or "REG_DWORD = 4", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow download restrictions" to "Enabled" and select "BlockDangerousDownloads" or "Block potentially dangerous or unwanted downloads".'
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38971r862949_chk'
  tag severity: 'low'
  tag gid: 'V-235752'
  tag rid: 'SV-235752r862950_rule'
  tag stig_id: 'EDGE-00-000036'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38934r766853_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
