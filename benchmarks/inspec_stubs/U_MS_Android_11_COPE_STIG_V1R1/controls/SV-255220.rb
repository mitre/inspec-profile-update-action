control 'SV-255220' do
  title 'The mobile operating system must allow only the Administrator (MDM) to perform the following management function: Enable/disable location services.'
  desc 'If a user is able to configure the security setting, the user could inadvertently or maliciously set it to a value that poses unacceptable risk to DOD information systems. An adversary could exploit vulnerabilities created by the weaker configuration to compromise DOD sensitive information.

SFR ID: FMT_MOF_EXT.1.2 #22'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device has location services on/off.

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Set user restrictions on parent".
2. Verify that "Disallow config location" is toggled to "On".
3. Verify that "Disallow share location" is toggled to "On".

On the Microsoft Android 11 device:
1. Open Settings >> Location.
2. Validate that Location Services is off for Work and Personal.

If location services has not been disabled, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to enable/disable location services.

On the EMM console:
1. Open "Set user restrictions on parent".
2. Toggle "Disallow config location" to "On".
3. Toggle "Disallow share location" to "On".'
  impact 0.3
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58833r870759_chk'
  tag severity: 'low'
  tag gid: 'V-255220'
  tag rid: 'SV-255220r870832_rule'
  tag stig_id: 'MSFT-11-005200'
  tag gtitle: 'PP-MDF-302340'
  tag fix_id: 'F-58777r869276_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
