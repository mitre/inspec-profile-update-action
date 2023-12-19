control 'SV-217801' do
  title 'Samsung Android must be configured to create a Knox Workspace.'
  desc 'The Knox Workspace is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Device configuration settings to confirm a legacy Knox Workspace has been created. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, verify that a legacy Knox Workspace has been created. 

On the Samsung Android device, verify the existence of the "Personal" and "Workspace" tabs on the App screen. 

If on the MDM console, a "legacy Knox Workspace" has not been created, or on the Samsung Android device the "Personal" and "Workspace" tabs are not present on the App screen, this is a finding.'
  desc 'fix', 'Configure Samsung Android to create a legacy Knox Workspace. 

On the MDM console, create a legacy Knox Workspace.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19017r362861_chk'
  tag severity: 'medium'
  tag gid: 'V-217801'
  tag rid: 'SV-217801r388482_rule'
  tag stig_id: 'KNOX-09-000265'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-19015r362862_fix'
  tag 'documentable'
  tag legacy: ['SV-103949', 'V-93863']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
