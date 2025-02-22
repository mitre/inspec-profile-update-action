control 'SV-94953' do
  title 'Samsung Android 8 with Knox must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the capability to back up to a locally connected system has been disabled. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Disable USB Media Player" check box in the "Android Restrictions" rule. 
2. Verify the "Disable USB Media Player" check box is selected. 

Note: Disabling USB Media Player will also disable USB MTP, USB mass storage, and USB vendor protocol (Smart Switch, KIES).

On the Samsung Android 8 with Knox device, connect the device to a PC USB connection.

Note: Do not use a DoD network-managed PC for this test!

On the PC:
1. Install and launch Samsung Smart Switch (Note: Samsung KIES for older devices) on the PC.
2. Verify the device does not connect with the Samsung Smart Switch program.

If the MDM console "Disable USB Media Player" is not set to "Disabled" or on the Samsung Android 8 with Knox device, it connects with the Samsung Smart Switch or KIES program, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to disable backup to locally connected systems.

On the MDM console, select the "Disable USB Media Player" check box in the "Android Restrictions" rule.

Note: Disabling USB Media Player will also disable USB MTP, USB mass storage, and USB vendor protocol (Smart Switch, KIES).'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80249'
  tag rid: 'SV-94953r1_rule'
  tag stig_id: 'KNOX-08-017300'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-87055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000097']
  tag nist: ['AC-20 (2)']
end
