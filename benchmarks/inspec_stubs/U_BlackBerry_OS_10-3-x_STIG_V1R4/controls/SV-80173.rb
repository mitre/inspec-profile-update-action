control 'SV-80173' do
  title 'BlackBerry OS 10.3 must require a valid password be successfully entered before the mobile device data is unencrypted.'
  desc 'Passwords provide a form of access control that prevents unauthorized individuals from accessing computing resources and sensitive data. Passwords may also be a source of entropy for generation of key encryption or data encryption keys. If a password is not required to access data, then this data is accessible to any adversary who obtains physical possession of the device. Requiring that a password be successfully entered before the mobile device data is unencrypted mitigates this risk.

Note: MDF PP v.2.0 requires a Password Authentication Factor and requires management of its length and complexity. It leaves open whether the existence of a password is subject to management. This STIGID addresses the configuration to require a password, which is critical to the cybersecurity posture of the device.

SFR ID: FIA_UAU_EXT.1.1'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if a valid password has been successfully entered before the mobile device data is unencrypted. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the Validation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Setting” and “BlackBerry” tabs.
5. Scroll down to the “Password" group of IT policy rules.
6. Check "Password required for work space".

On the BlackBerry device, do the following:
1. From either the Work Space or Personal Space, navigate to Settings >> BlackBerry Balance.
2. Verify "Work Password" is toggled to the right and dimmed (Not accessible).

If the BES IT Policy rule "Password Required for Work Space" is not selected, or on the BlackBerry device the "Work Password" is not toggled to the right and dimmed (Not accessible) this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Password" group of IT policy rules.
7. Select the check box next to the IT Policy "Password required for work".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.7
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66313r3_chk'
  tag severity: 'high'
  tag gid: 'V-65683'
  tag rid: 'SV-80173r1_rule'
  tag stig_id: 'BB10-3X-000100'
  tag gtitle: 'PP-MDF-201001'
  tag fix_id: 'F-71701r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
