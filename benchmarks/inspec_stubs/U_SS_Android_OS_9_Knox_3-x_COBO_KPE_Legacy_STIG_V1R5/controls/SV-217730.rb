control 'SV-217730' do
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
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18948r362338_chk'
  tag severity: 'high'
  tag gid: 'V-217730'
  tag rid: 'SV-217730r617462_rule'
  tag stig_id: 'KNOX-09-000985'
  tag gtitle: 'PP-MDF-301140'
  tag fix_id: 'F-18946r362339_fix'
  tag 'documentable'
  tag legacy: ['SV-103707', 'V-93621']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
