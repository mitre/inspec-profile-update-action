control 'SV-80185' do
  title 'BlackBerry OS 10.3 must protect data at rest on removable storage media. The requirement applies only to Work - Only Activation types.'
  desc "The BlackBerry device must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #26"
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry protects data at rest on removable storage media. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of the IT policy.
6. Verify "Force media card encryption" is checked".

On the BlackBerry device:
1. Ensure a media card is installed in the BlackBerry.
2. Navigate to Settings >> Security and Privacy >> Encryption.
3. Verify that "Media Card Encryption" is not a listed option.

If the BES IT policy rule "Force media card encryption" is not selected or the BlackBerry device "Media Card Encryption" is a listed option, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Select the check box next to the IT Policy "Force card encryption".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.7
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66349r3_chk'
  tag severity: 'high'
  tag gid: 'V-65695'
  tag rid: 'SV-80185r1_rule'
  tag stig_id: 'BB10-3X-000210'
  tag gtitle: 'PP-MDF-201012'
  tag fix_id: 'F-71737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
