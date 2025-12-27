control 'SV-221571' do
  title 'Google Data Synchronization must be disabled.'
  desc 'Disables data synchronization in Google Chrome using Google-hosted synchronization services and prevents users from changing this setting. If you enable this setting, users cannot change or override this setting in Google Chrome. If this policy is left not set the user will be able to enable Google Sync.  Google Sync is used to sync information between different user devices, this data is then stored on Google owned servers. The synced data may consist of information such as email, calendars, viewing history, etc. This feature must be disabled because the organization does not have control over the servers the data is stored on.'
  desc 'check', 'Universal method:        
  1. In the omnibox (address bar) type chrome://policy        
  2. If SyncDisabled is not displayed under the Policy Name column or it is not set to true under the Policy Value column, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the SyncDisabled value name does not exist or its value data is not set to 1, then this is a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
    Policy Name: Disable synchronization of data with Google
    Policy State: Enabled
    Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23286r415840_chk'
  tag severity: 'medium'
  tag gid: 'V-221571'
  tag rid: 'SV-221571r615937_rule'
  tag stig_id: 'DTBC-0020'
  tag gtitle: 'SRG-APP-000047'
  tag fix_id: 'F-23275r415841_fix'
  tag 'documentable'
  tag legacy: ['SV-57593', 'V-44759']
  tag cci: ['CCI-001374']
  tag nist: ['AC-4 (15)']
end
