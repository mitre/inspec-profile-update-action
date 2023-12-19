control 'SV-84749' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Disable the ability of the Edge browser to cache passwords in the Password Manager.'
  desc 'Access to websites that require authentication can be streamlined for faster logon if credentials like passwords can be saved. But eliminating password prompts leaves protected websites vulnerable to access without a logon challenge.

Disallowing password caching mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if the browser is blocked from being able to cache web site passwords. If feasible, use a spare device to determine if bringing up the "Offer to save passwords" setting shows that it's disabled.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "allow password manager".
3. Verify that setting restriction is turned off/disallowed.

On the Windows 10 Mobile device:

1. Go to "All apps" page. From the Start page swipe left to reveal.
2. Navigate to browser app "Microsoft Edge", then tap to launch.
3. At the bottom right of the page, look for the menu button which is "..." and tap on it.
4. Look for "Settings" in menu list and Tap to launch.
5. Scroll through settings page and look for section called "Advanced settings" and Tap on the button below called "View advanced settings". 
6. Verify that the toggle setting under "Privacy and services" called "Offer to save passwords" is both disabled/read-only and set to "Off".

If the MDM does not disable the policy for setting for "allow password manager" or if on the phone the "Offer to save passwords" is not disabled/read-only and set to "Off" in the specified location on the "Advanced settings" screen of the Microsoft Edge app, this is a finding.)
  desc 'fix', 'Configure the MDM system with a security policy that requires the "allow password manager" capability to be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy to managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70603r1_chk'
  tag severity: 'low'
  tag gid: 'V-70127'
  tag rid: 'SV-84749r1_rule'
  tag stig_id: 'MSWM-10-910505'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
