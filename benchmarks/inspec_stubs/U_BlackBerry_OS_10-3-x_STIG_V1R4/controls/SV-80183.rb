control 'SV-80183' do
  title 'BlackBerry OS 10.3 must not allow use of developer modes.'
  desc 'Developer modes expose features of the BlackBerry device that are not available during standard operation. When the Development Mode is enabled on BlackBerry 10 OS devices, the user has the capability to sideload apps to either the Work Space or Personal Space. Disabling this feature removes the capability for a user to sideload apps. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD-sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #24'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry does not allow developer modes. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Setting” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Allow development mode access to work space" is not selected.
7. Verify "Restrict development mode" is selected.

On the BlackBerry device:
1. From either the Work Space or Personal Space, navigate to Settings >> Security and Privacy >> Development Mode.
2. Verify "Development Mode" is toggled to the left (off) and not accessible.

If the BES IT policy rule "Restrict development mode" is not selected or the BlackBerry device "Development Mode" is toggled to the right (on) or accessible, this is a finding.

Note: The BES IT Policy rule "Allow development mode access to work space" may not be visible once the BES IT Policy rule "Restrict development mode" is selected.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:

1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Unselect the check box next to the IT policy "Allow development mode access to work space".
8. Select the check box next to the IT Policy "Restrict Development Mode".
9. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66347r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65693'
  tag rid: 'SV-80183r1_rule'
  tag stig_id: 'BB10-3X-000190'
  tag gtitle: 'PP-MDF-201010'
  tag fix_id: 'F-71735r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
