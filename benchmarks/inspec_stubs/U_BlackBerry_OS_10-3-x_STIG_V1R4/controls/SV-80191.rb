control 'SV-80191' do
  title 'BlackBerry OS 10.3 must disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled.'
  desc 'Many software systems automatically send diagnostic data to the manufacturer or a third party. This data enables the developers to understand real world field behavior and improve the product based on that information. Unfortunately, it can also reveal information about what DoD users are doing with the systems and what causes them to fail. An adversary embedded within the software development team or elsewhere could use the information acquired to breach BlackBerry OS 10.3 smartphone security. Disabling automatic transfer of such information mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1#45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry disables automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled. This procedure is performed on only on the BES console.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Apps” group of IT policy rules.
6. Verify "Allow wireless service provider apps" is not selected.

If the BES IT policy rule "Allow wireless service provider apps" is selected, this is a finding. 

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Apps” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow wireless service provider apps".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66355r3_chk'
  tag severity: 'low'
  tag gid: 'V-65701'
  tag rid: 'SV-80191r1_rule'
  tag stig_id: 'BB10-3X-000290'
  tag gtitle: 'PP-MDF-201021'
  tag fix_id: 'F-71743r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
