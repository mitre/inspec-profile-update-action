control 'SV-103851' do
  title 'Samsung Android must be configured to create a Knox Workspace.'
  desc 'The Knox Workspace is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Device configuration settings to confirm that a Knox Workspace has been created. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, verify that a Knox Workspace has been created. 

On the Samsung Android device, verify the existence of the "Personal" and "Workspace" tabs on the App screen. 

If on the MDM console, a "Knox Workspace" has not been created, or on the Samsung Android device the "Personal" and "Workspace" tabs are not present on the App screen, this is a finding.'
  desc 'fix', 'Configure Samsung Android to create a Knox Workspace. 

On the MDM console, create a Knox Workspace.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93765'
  tag rid: 'SV-103851r1_rule'
  tag stig_id: 'KNOX-09-000260'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-100011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
