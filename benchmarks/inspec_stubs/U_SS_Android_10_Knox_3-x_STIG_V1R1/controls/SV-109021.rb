control 'SV-109021' do
  title 'Samsung Android must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device is enforcing a screen-lock policy that will lock the display after a period of inactivity.

This requirement is met by enforcing a secure "Screen lock type". 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device password requirements section, verify the "minimum password quality" is set to one of the following: "Something", "Numeric", "Numeric(Complex)", "Alphabetic", "Alphanumeric", or "Complex".

On the Samsung Android device, do the following:
1. Open Settings >> Lock screen >> Screen lock type.
2. Enter current password.
3. Verify that "Swipe" and "None" are unavailable for selection.

If on the management tool the "minimum password quality" is set to "Unspecified", or on the Samsung Android device the Screen lock types "Swipe" or "None" are available for selection, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable a screen-lock policy that will lock the display after a period of inactivity.

This requirement is met by enforcing a secure "Screen lock type". 

On the management tool, in the device password requirements section, set the "minimum password quality" to one of the following: "Something", "Numeric", "Numeric(Complex)", "Alphabetic", "Alphanumeric", or "Complex".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3.x'
  tag check_id: 'C-98767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99917'
  tag rid: 'SV-109021r1_rule'
  tag stig_id: 'KNOX-10-000300'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-105601r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
