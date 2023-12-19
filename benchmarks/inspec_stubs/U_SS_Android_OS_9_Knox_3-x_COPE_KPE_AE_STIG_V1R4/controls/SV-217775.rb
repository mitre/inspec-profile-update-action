control 'SV-217775' do
  title 'Samsung Android must be configured to enable encryption for data at rest on removable storage media or alternately, the use of removable storage media must be disabled.'
  desc "The mobile operating system must ensure that the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #21, #47f"
  desc 'check', 'Review device configuration settings to confirm that mounting of physical storage media is disallowed or Knox external storage encryption is enabled. 

If the mobile device does not support removable media, this procedure is not applicable and is not a finding. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

Confirm if Method #1 or Method #2 is used at the Samsung device site and follow the appropriate procedure. 

**** 

Method #1: On the MDM console, for the device, in the "Android user restrictions" group, verify that "disallow mount physical media" is selected. 

On the Samsung Android device, verify that a MicroSD card cannot be mounted. 

If on the MDM console "disallow mount physical media" is not selected, or a MicroSD card can be mounted by the Samsung Android device, this is a finding. 

**** 

Method #2: On the MDM console, for the device, in the "Knox encryption" group, verify that "enable external storage encryption" is selected. 

On the Samsung Android device, verify that a MicroSD card must be encrypted before use. 

If on the MDM console "enable external storage encryption" is not selected, or a MicroSD card can be used on the Samsung Android device without first being encrypted, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disallow mount of physical storage media or enable Knox external storage encryption. 

If the mobile device does not support removable media, this guidance is not applicable. 

Do one of the following: 
- Method #1: Disallow mounting of physical storage media. 
- Method #2: Enable external storage encryption. 

**** 

Method #1: On the MDM console, for the device, in the "Android user restrictions" group, select "disallow mount physical media". 

**** 

Method #2: On the MDM console, for the device, in the "Knox encryption" group, select "enable external storage encryption".'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE AE'
  tag check_id: 'C-18992r362618_chk'
  tag severity: 'high'
  tag gid: 'V-217775'
  tag rid: 'SV-217775r617462_rule'
  tag stig_id: 'KNOX-09-000980'
  tag gtitle: 'PP-MDF-301140'
  tag fix_id: 'F-18990r362619_fix'
  tag 'documentable'
  tag legacy: ['SV-103899', 'V-93813']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
