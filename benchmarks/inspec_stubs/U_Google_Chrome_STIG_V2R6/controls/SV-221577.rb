control 'SV-221577' do
  title 'Importing of saved passwords must be disabled.'
  desc 'Importing of saved passwords should be disabled as it could lead to unencrypted account passwords stored on the system from another browser to be viewed. This policy forces the saved passwords to be imported from the previous default browser if enabled. If enabled, this policy also affects the import dialog. If disabled, the saved passwords are not imported. If it is not set, the user may be asked whether to import, or importing may happen automatically.'
  desc 'check', 'Universal method:        
   1. In the omnibox (address bar) type chrome://policy        
   2. If ImportSavedPasswords is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the ImportSavedPasswords value name does not exist or its value data is not set to 0, then this is a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
   Policy Name: Import saved passwords from default browser on first run
   Policy State: Disabled
   Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23292r415858_chk'
  tag severity: 'medium'
  tag gid: 'V-221577'
  tag rid: 'SV-221577r615937_rule'
  tag stig_id: 'DTBC-0029'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23281r415859_fix'
  tag 'documentable'
  tag legacy: ['SV-57609', 'V-44775']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
