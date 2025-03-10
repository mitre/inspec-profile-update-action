control 'SV-258392' do
  title 'Google Android 14 must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review managed Google Android 14 device configuration settings to determine if the capability to back up to a locally connected system has been disabled. 

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 14 device. 

On the EMM console:

COBO and COPE:

1. Open "Device owner management".
2. Verify "Enable backup service" is toggled to "OFF".

On the managed Google Android 14 device:

COBO:

1. Go to Settings >> System >> Backup.
2. Verify Backup settings is "Not available".

COPE:

1. Go to Settings >> System >> Backup.
2. Select "Work".
3. Verify Backup settings is "Not available".

If the EMM console device policy is not set to disable the capability to back up to a locally connected system or on the managed Google Android 14 device, the device policy is not set to disable the capability to back up to a locally connected system, and this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to disable backup to locally connected systems.

On the EMM console:

COBO and COPE:

1. Open "Device owner management".
2. Toggle "Enable backup service" to "OFF".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62133r928199_chk'
  tag severity: 'medium'
  tag gid: 'V-258392'
  tag rid: 'SV-258392r928201_rule'
  tag stig_id: 'GOOG-14-008500'
  tag gtitle: 'PP-MDF-333240'
  tag fix_id: 'F-62057r928200_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
