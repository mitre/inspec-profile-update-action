control 'SV-103997' do
  title 'Samsung Android must be configured to enable encryption for data at rest on removable storage media or alternately, the use of removable storage media must be disabled.'
  desc "The mobile operating system must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #21, #47f"
  desc 'check', 'Review device configuration settings to determine if Knox external storage encryption is enabled. 

If the mobile device does not support removable media, this procedure is not applicable and is not a finding. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox encryption" group, verify that "enable external storage encryption" is selected. 

On the Samsung Android device, verify that a MicroSD card must be encrypted before use. 

If on the MDM console "enable external storage encryption" is not selected, or a MicroSD card can be used on the Samsung Android device without first being encrypted, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable Knox external storage encryption. 

If the mobile device does not support removable media, this guidance is not applicable. 

On the MDM console, for the device, in the "Knox encryption" group, select "enable external storage encryption".'
  impact 0.7
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(Legacy)'
  tag check_id: 'C-93229r1_chk'
  tag severity: 'high'
  tag gid: 'V-93911'
  tag rid: 'SV-103997r1_rule'
  tag stig_id: 'KNOX-09-000985'
  tag gtitle: 'PP-MDF-301140'
  tag fix_id: 'F-100159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
