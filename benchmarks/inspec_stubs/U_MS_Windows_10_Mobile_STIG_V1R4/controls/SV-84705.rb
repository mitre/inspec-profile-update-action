control 'SV-84705' do
  title 'Windows 10 Mobile must enforce an application installation policy by specifying an application whitelist.'
  desc 'Requiring all authorized applications to be in an application whitelist prevents the execution of any applications (e.g., unauthorized, malicious) that are not part of the whitelist. Failure to configure an application whitelist properly could allow unauthorized and malicious applications to be downloaded, installed, and executed on the mobile device, causing a compromise of DoD data accessible by these applications.

The application whitelist, in addition to controlling the installation of applications on the MD, must control user access/execution of all core applications (included in the operating system (OS) by the OS vendor) and pre-installed applications (provided by the MD vendor and wireless carrier), or the MD must provide an alternate method of restricting user access/execution to core and pre-installed applications.

SFR ID: FMT_SMF_EXT.1.1 #10b'
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if the mobile device has an application whitelist configured. If feasible, use a spare device to determine if an application whitelist is configured. 

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Display policy area for managing allowed applications.
2. Verify a policy exists that creates an application whitelist of allowed applications.
3. Verify all applications on the list of whitelisted applications have been approved by the Authorizing Official (AO).
4. Verify the application whitelist policy has been deployed to the target devices under management on the MDM console.
5. This list can be empty if no applications have been approved. See the STIG supplemental document for additional information.

On the Windows 10 Mobile device:

1. Go to "All apps" page. From the Start page swipe left to reveal.
2. If the whitelist policy has been successfully deployed the majority of apps listed should have a dimmed appearance and have the text "Unavailable" under each restricted application.
3. Look for several apps that are not included in the application whitelist.
4. Determine if any app can be launched by tapping on its icon.
5. Verify that the app both has the text "Unavailable" under its title and that when launched this text appears on a pop-up page: "This app is disabled by your enterprise policy".

If the application whitelist policy doesn't exist or doesn't only contain authorized applications or hasn't been deployed to targeted devices under enrollment or on the device any non-whitelisted app can be launched, this is a finding.)
  desc 'fix', "Setup an Application whitelist (authorized apps) using an MDM for Windows 10 Mobile. 

Deploy the policy on managed devices.

This will provide an authorized repository of applications which can be installed on a managed user's device."
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70559r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70083'
  tag rid: 'SV-84705r1_rule'
  tag stig_id: 'MSWM-10-200306'
  tag gtitle: 'PP-MDF-201007'
  tag fix_id: 'F-76319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
