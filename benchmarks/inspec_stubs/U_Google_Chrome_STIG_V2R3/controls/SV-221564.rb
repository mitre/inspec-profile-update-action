control 'SV-221564' do
  title 'The default search providers name must be set.'
  desc "Specifies the name of the default search provider that is to be used, if left empty or not set, the host name specified by the search URL will be used. This policy is only considered if the 'DefaultSearchProviderEnabled' policy is enabled. When doing internet searches it is important to use an encrypted connection via https."
  desc 'check', 'Universal method:        
   1. In the omnibox (address bar) type chrome://policy        
   2. If DefaultSearchProviderName is displayed under the Policy Name column or it is not set to an organization approved encrypted search provider that corresponds to the encrypted search provider set in DTBC-0008(ex. Google Encrypted, Bing Encrypted) under the Policy Value column, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the DefaultSearchProviderName value name does not exist or it is not set to an organization approved encrypted search provider that corresponds to the encrypted search provider set in DTBC-0008(ex. Google Encrypted, Bing Encrypted), then this is a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\Default search provider\\
    Policy Name: Default search provider name
    Policy State: Enabled
    Policy Value: set to an organization approved encrypted search provider that corresponds to the encrypted search provider set in DTBC-0008(ex. Google Encrypted, Bing Encrypted)'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23279r415819_chk'
  tag severity: 'medium'
  tag gid: 'V-221564'
  tag rid: 'SV-221564r615937_rule'
  tag stig_id: 'DTBC-0007'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23268r415820_fix'
  tag 'documentable'
  tag legacy: ['SV-57567', 'V-44733']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
