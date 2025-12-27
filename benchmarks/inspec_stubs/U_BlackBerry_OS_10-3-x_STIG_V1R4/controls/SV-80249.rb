control 'SV-80249' do
  title 'BlackBerry OS 10.3 must protect data at rest on built-in storage media for Personal space. This requirement only applies to Work and Personal  Corporate and Work and personal - Regulated activation types.'
  desc "The BlackBerry device must ensure the data being written to the mobile device's built-in storage media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read storage media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #25"
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry protects data at rest on built-in storage media for Personal space.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and privacy” group of IT policy rules.
6. Verify "Force personal space data encryption" is selected.

On the BlackBerry device: 
1. From either the Work Space or Personal Space, navigate to "Settings" >> "Security and Privacy" >> "Encryption".
2. Verify "Device Encryption" is toggled to the right (on) and not accessible.

If the BES IT Policy rule "Force personal space data encryption" is not selected, or on the BlackBerry device if "Device Encryption" is toggled to the left (off) and accessible, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and privacy” group of IT policy rules.
7. Select the check box next to the IT Policy "Force personal space data encryption ".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.7
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66441r2_chk'
  tag severity: 'high'
  tag gid: 'V-65759'
  tag rid: 'SV-80249r1_rule'
  tag stig_id: 'BB10-3X-020300'
  tag gtitle: 'PP-MDF-201011'
  tag fix_id: 'F-71829r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
