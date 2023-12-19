control 'SV-231000' do
  title 'Samsung Android must be enrolled as a COPE/COBO device.'
  desc 'The Knox Workspace is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device. 

****

Validation Procedure for Method #1: Work profile for company-owned devices (COPE)

On the management tool, verify that the default enrollment is set to "Work profile for company-owned devices".

On the Samsung Android device: 
1. Open Settings >> Work profile >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.
3. Go to the app drawer.
4. Verify that a "Personal" and "Work" tab are present.

If on the management tool the default enrollment is not set as "Work profile for company-owned devices", or on the Samsung Android device the "Personal" and "Work" tabs are not present or the management tool Agent is not listed, this is a finding.

****

Validation Procedure for Method #2: Fully Managed (COBO)

On the management tool, verify that the default enrollment is set as "Fully managed".

On the Samsung Android device: 
1. Open Settings >> Biometric and security >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.

****

If on the management tool the default enrollment is not set as "Fully managed", or the management tool Agent is not listed, this is a finding.'
  desc 'fix', 'Enroll the Samsung Android device in a DoD-approved use case by either of the following methods:

Method #1: Work profile for company-owned devices (COPE)

On the management tool, configure the default enrollment as "Work profile for company-owned devices".

****

Method #2: Fully Managed (COBO)

On the management tool, configure the default enrollment as "Fully managed".

****

Refer to the management tool documentation to determine how to configure the device enrollment.'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33930r592492_chk'
  tag severity: 'medium'
  tag gid: 'V-231000'
  tag rid: 'SV-231000r607691_rule'
  tag stig_id: 'KNOX-11-018500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33903r592493_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
