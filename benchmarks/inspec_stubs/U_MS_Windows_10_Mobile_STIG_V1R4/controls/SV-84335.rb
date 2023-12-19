control 'SV-84335' do
  title 'Windows 10 Mobile must disable the Windows Store.'
  desc 'Forcing all applications to be installed from authorized application repositories can prevent unauthorized and malicious applications from being installed and executed on mobile devices. Allowing such installations and executions could cause a compromise of DoD data accessible by these unauthorized/malicious applications. A risk assessment for the download of apps from the Microsoft Store has not yet been completed by the DoD, and therefore, should not be accessed for the download of authorized non-managed apps (personal apps) at this time.

SFR ID: FMT_SMF_EXT.1.1 #10a'
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if the Windows Store is accessible. If feasible, use a spare device to determine if the "Store" application is accessible.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Display the policy that restricts the use of a Store application.
2. Verify that this policy is set to be disabled.

On Windows 10 Mobile device:

1. From the Start page or on the Applications page (swipe to the left from the Start page), find the Store application icon.
Note: The Store icon should appear dim.
2. Tap on the Store app to attempt to launch it. A message should be displayed:
"App disabled. This app has been disabled by company policy. Contact your company's support person for help."

If the MDM does not have a policy that disables the Store application or if the Windows Store app can be successfully launched, this is a finding.)
  desc 'fix', 'Configure an application control policy using an MDM for Windows 10 Mobile to disable the Store application. 

Deploy the policy to managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70155r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69713'
  tag rid: 'SV-84335r1_rule'
  tag stig_id: 'MSWM-10-200305'
  tag gtitle: 'PP-MDF-201006'
  tag fix_id: 'F-75917r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
