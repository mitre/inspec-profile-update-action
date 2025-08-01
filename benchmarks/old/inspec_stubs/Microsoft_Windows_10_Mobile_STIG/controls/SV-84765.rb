control 'SV-84765' do
  title 'Windows 10 Mobile devices must be upgraded to the Windows 10 Mobile Enterprise edition.  Enterprise edition provides the ability to leverage several enhanced controls that have a dependency on the enterprise edition.'
  desc 'During ongoing operating system development, Windows 10 has a cadence of MOS updates that add new features including improved enterprise and security capabilities as well as fixes to issues discovered after its initial release. Several key security related controls are not possible when the Enterprise version of Windows 10 mobile is not used, including:

-disable automatic updates of Windows 10 Mobile
-disable sending device diagnostic data to Microsoft

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the MOS has been upgraded to Windows 10 Mobile Enterprise. If feasible, use a spare device to determine if bringing up the About/Device Information page shows it is running the correct Windows 10 Mobile edition.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the policy package used for distributing a license upgrade to Windows 10 Mobile Enterprise.
3. Verify that package exists and has been deployed to all Windows 10 Mobile devices.

On the Windows 10 Mobile device:

1. Navigate to Settings/System/About (tap on About to open).
2. On About page look for section called "Device information". 
3. Verify that the line entitled "Software:" contains the text "Windows 10 Mobile Enterprise".

If the MDM does not have a configuration package to distribute a license upgrade to Windows 10 Mobile Enterprise or if on the phone the "Software:" text is not set to "Windows 10 Mobile Enterprise" in the specified location on the "About" page of the Settings/System area, this is a finding.'
  desc 'fix', 'Configure the MDM system with a deployment package policy that contains a licensing upgrade leveraging the "WindowsLicensing/UpgradeEditionWithLicense" Windows licensing policy to perform an in-place upgrade of Windows 10 Mobile devices from Windows 10 Mobile to Windows 10 Mobile Enterprise. 

Deploy the MDM policy to managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70143'
  tag rid: 'SV-84765r1_rule'
  tag stig_id: 'MSWM-10-912419'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76379r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
