control 'SV-214866' do
  title 'The macOS system must obtain updates from a DoD-approved update server.'
  desc 'Software update configuration. Point to DOD approved update server. Configure for automatic install of critical updates.'
  desc 'check', 'To check if the CatalogURL is configured, run the following command:

defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL

2017-11-30 22:21:41.805 defaults[1205:9595] 

The domain/default pair of (/Library/Preferences/com.apple.SoftwareUpdate.plist, CatalogURL) does not exist.

If the output is not an error indicating the item "does not exist" or the output is not a DoD-approved update server, this is a finding.

Note: Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).'
  desc 'fix', 'To remove the Apple software list from the system configuration run the following command:

sudo defaults delete /Library/Preferences/com.apple.SoftwareUpdate.plist CatalogURL'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16066r397170_chk'
  tag severity: 'medium'
  tag gid: 'V-214866'
  tag rid: 'SV-214866r609363_rule'
  tag stig_id: 'AOSX-13-000552'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16064r397171_fix'
  tag 'documentable'
  tag legacy: ['SV-96325', 'V-81611']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
