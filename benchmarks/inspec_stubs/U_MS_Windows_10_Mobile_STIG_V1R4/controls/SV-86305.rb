control 'SV-86305' do
  title 'Windows10 Mobile must be running at a minimum an OS build number of 10.0.15063.608  or higher to meet all requirements in the STIG.'
  desc 'During ongoing operating system development, Windows 10 has a cadence of MOS updates that adds new features, including improved enterprise and security capabilities as well as fixes to issues discovered after its initial release. Requirements and issues were discovered that were resolved through improvements in new Windows 10 Mobile OS releases. As a result, to completely meet all requirements outlined in the DOD STIG, devices used by DoD must have or exceed the minimum build numbers listed in the requirements.

SFR #: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'This procedure is performed only on the Windows 10 Mobile device.

1. From the Start page, swipe to the left to show the App list.
2. Find and tap on "Settings".
3. Tap on "System". 
4. Scroll down to the bottom and tap on "About".
5. Under the section titled "Device information", tap on the "More info" button.
6. Verify the "OS build" number is greater than or equal to 10.0.15063.608 to meet all DISA STIG requirements.

If the "OS build" number under Settings/System/About/More info is not greater than or equal to 10.0.15063.608, this is a finding.'
  desc 'fix', 'Ensure that the devices being used are running the required or higher Windows 10 Mobile operating system builds.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-71989r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71681'
  tag rid: 'SV-86305r2_rule'
  tag stig_id: 'MSWM-10-902420'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-78007r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
