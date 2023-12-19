control 'SV-221593' do
  title 'Chrome Cleanup reporting must be disabled.'
  desc 'If unset, should Chrome Cleanup detect unwanted software, it may report metadata about the scan to Google in accordance with policy set by “SafeBrowsingExtendedReportingEnabled”. Chrome Cleanup will then ask the user if they wish to clean up the unwanted software. The user can choose to share results of the cleanup with Google to assist with future unwanted software detection. These results contain file metadata and registry keys as described by the Chrome Privacy Whitepaper.
If set to “false”, should Chrome Cleanup detect unwanted software, it will not report metadata about the scan to Google, overriding any policy set by “SafeBrowsingExtendedReportingEnabled”. Chrome Cleanup will ask the user if they wish to clean up the unwanted software. Results of the cleanup will not be reported to Google and the user will not have the option to do so.
If set to “true”, should Chrome Cleanup detect unwanted software, it may report metadata about the scan to Google in accordance with policy set by “SafeBrowsingExtendedReportingEnabled”. Chrome Cleanup will ask the user if they wish to clean up the unwanted software. Results of the cleanup will be reported to Google and the user will not have the option to prevent it.
This policy is available only on Windows instances that are joined to a Microsoft Active Directory domain.'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy
 2. If "ChromeCleanupReportingEnabled" is not displayed under the "Policy Name" column or it is not set to "False", this is a finding.
Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the "ChromeCleanupReportingEnabled" value name does not exist or its value data is not set to "0", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the “group policy editor” tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome
Policy Name: Control how Chrome Cleanup reports data to Google
Policy State: Disabled
Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23308r415906_chk'
  tag severity: 'medium'
  tag gid: 'V-221593'
  tag rid: 'SV-221593r615937_rule'
  tag stig_id: 'DTBC-0061'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-23297r415907_fix'
  tag 'documentable'
  tag legacy: ['SV-96307', 'V-81593']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
