control 'SV-241221' do
  title 'Samsung Android must be enrolled as a COPE/COBO device.'
  desc 'The Knox Workspace is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android device configuration settings to confirm that the device is enrolled in a DoD-approved use case.

Confirm if Method #1, #2, #3, or #4 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device. 

****

Method #1: Fully managed with work profile [KPE(AE) COPE deployment]

On the management tool, verify that the default enrollment is set to "Fully managed with work profile".

On the Samsung Android device, do the following:
1. Open Settings >> Biometric and security >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.
3. Go to the app drawer.
4. Verify that a "Personal" and "Work" tab are present.

If on the management tool the default enrollment is not set as "Fully managed with work profile", or on the Samsung Android device the "Personal" and "Work" tabs are not present, or the management tool Agent is not listed, this is a finding.

****

Method #2: Legacy managed with Legacy Workspace [KPE(Legacy) COPE deployment]

On the management tool, verify that the default enrollment is set to "Legacy managed with Legacy Workspace".

On the Samsung Android device, do the following:
1. Open Settings >> Biometric and security >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.
3. Go to the app drawer.
4. Verify that a "Personal" and "Workspace" tab are present.

If on the management tool the default enrollment is not set as "Legacy managed with Legacy Workspace", or on the Samsung Android device the "Personal" and "Work" tabs are not present, or the management tool Agent is not listed, this is a finding.

****

Method #3: Fully managed [KPE(AE) COBO deployment]

On the management tool, verify that the default enrollment is set as "Fully managed".

On the Samsung Android device, do the following:
1. Open Settings >> Biometric and security >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.

If on the management tool the default enrollment is not set as "Fully managed", or the management tool Agent is not listed, this is a finding.

****

Method #4: Legacy managed [KPE(Legacy) COBO deployment]

On the management tool, verify that the default enrollment is set as "Legacy managed".

On the Samsung Android device, do the following:
1. Open Settings >> Biometric and security >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.

If on the management tool the default enrollment is not set as "Legacy managed", or the management tool Agent is not listed, this is a finding.'
  desc 'fix', 'Enroll the Samsung Android device in a DoD-approved use case.

Do one of the following:
- Method #1: Fully managed with work profile [KPE(AE) COPE deployment]
- Method #2: Legacy managed with Legacy Workspace [KPE(Legacy) COPE deployment]
- Method #3: Fully managed [KPE(AE) COBO deployment]
- Method #4: Legacy managed [KPE(Legacy) COBO deployment]

****

Method #1: Fully managed with work profile [KPE(AE) COPE deployment]

On the management tool, configure the default enrollment as "Fully managed with work profile".

****

Method #2: Legacy managed with Legacy Workspace [KPE(Legacy) COPE deployment]

On the management tool, configure the default enrollment as "Legacy managed with Legacy Workspace".

****

Method #3: Fully managed [KPE(AE) COBO deployment]

On the management tool, configure the default enrollment as "Fully managed".

****

Method #4: Legacy managed [KPE(Legacy) COBO deployment]

On the management tool, configure the default enrollment as "Legacy managed".

****

Refer to the management tool documentation to determine how to configure the device enrollment.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44497r680302_chk'
  tag severity: 'medium'
  tag gid: 'V-241221'
  tag rid: 'SV-241221r680304_rule'
  tag stig_id: 'KNOX-10-009600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-44456r680303_fix'
  tag 'documentable'
  tag legacy: ['SV-109075', 'V-99971']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
