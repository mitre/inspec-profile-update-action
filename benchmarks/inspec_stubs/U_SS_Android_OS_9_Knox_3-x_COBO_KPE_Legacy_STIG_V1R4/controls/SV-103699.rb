control 'SV-103699' do
  title 'Samsung Android must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review device configuration settings to confirm backup to locally connected systems has been disabled. 

Disabling backup to locally connected systems is validated by the validation procedure in "Disable USB mass storage", which is included in KNOX-09-000685.

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "disable USB media player" is selected. 

Connect the Samsung Android device to a non-DoD network-managed PC with a USB cable. 

On the PC, browse the mounted Samsung Android device and verify that it does not display any folders or files. 

If on the MDM console "disable USB media player" is not selected, or the PC can mount and browse folders and files on the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable backup to locally connected systems. 

Disabling backup to locally connected systems is implemented by the configuration policy rule "Disable USB mass storage", which is included in KNOX-09-000685.

On the MDM console, for the device, in the "Knox restrictions" group, select "disable USB media player".'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(Legacy)'
  tag check_id: 'C-92929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93613'
  tag rid: 'SV-103699r1_rule'
  tag stig_id: 'KNOX-09-000845'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-99857r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
