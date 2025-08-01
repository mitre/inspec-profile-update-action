control 'SV-228591' do
  title 'Google Android 11 must allow only the Administrator (EMM) to perform the following management function: enable/disable location services.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DoD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DoD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #22'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device has location services on/off.

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM console, do the following:
1. Open "Set user restrictions on parent".
2. Verify that "Disallow config location" is toggled to On.
3. Verify that "Disallow share location" is toggled to On.

On the Google device, do the following:
1. Open Settings >> Location.
2. Validate that Location Services is off for Work and Personal.

If the mobile device has location services enabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 11 device to enable/disable location services.

On the EMM console:
1. Open "Set user restrictions on parent".
2. Toggle "Disallow config location" to On.
3. Toggle "Disallow share location" to On.'
  impact 0.3
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30826r505598_chk'
  tag severity: 'low'
  tag gid: 'V-228591'
  tag rid: 'SV-228591r619923_rule'
  tag stig_id: 'GOOG-11-005200'
  tag gtitle: 'PP-MDF-302340'
  tag fix_id: 'F-30803r505599_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
