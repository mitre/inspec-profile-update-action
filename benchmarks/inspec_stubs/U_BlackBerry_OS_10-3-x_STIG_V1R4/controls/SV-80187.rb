control 'SV-80187' do
  title 'BlackBerry OS 10.3 must display the DoD advisory warning message each time the device restarts. This requirement does not apply to Work and personal - Corporate.'
  desc %q(The BlackBerry OS 10.3 is required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. Required banners help ensure that DoD can audit and monitor the activities of mobile device users without legal restriction.

System use notification messages can be displayed when individuals first access or unlock the mobile device. The banner shall be implemented as a "click-through" banner at device unlock (to the extent permitted by the operating system). A "click through" banner prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating “OK.”

The approved DoD text must be used exactly as required in the KS referenced in DoDI 8500.01. For devices accommodating banners of 1300 characters, the banner text is: 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

For devices with severe character limitations, the banner text is: 

I've read & consent to terms in IS user agreem't.

The administrator must configure the banner text exactly as written without any changes.

SFR ID: FMT_SMF_EXT.1.1 #36)
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry displays the DoD advisory warning message at start-up or each time the user unlocks the device. This procedure is performed on both the BES console and on a managed mobile device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and privacy” group of IT policy rules.
6. Verify "Display organization notice after device restart" is selected.

On the BlackBerry device: 
1. From either the Work Space or Personal Space, while holding the Power button, select "Restart" to reboot the device. 
2. When the device restarts, ensure the required DoD warning banner (see VulDescription) is displayed on the lock screen.

If the BES IT policy rule "Display Organization Notice After Device Restart" is not selected or on the BlackBerry device the required banner is not displayed after the device restarts, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and privacy” group of IT policy rules.
7. Select the check box next to the IT Policy "Display organization notice after device restart".
8. Click "Save".

Note: If the organization Notice or the device profile does not exist, complete the following.

Create an Organizational Notice:
1. On the menu bar, click “Settings”.
2. In the left pane, expand “General settings”.
3. Click “Organization notices”.
4. Click "+" at the right side of the screen. 
5. In the “Name” field, type a name for the organization notice.
6. In the “Device language” drop-down list, select the language to use as the default language for the organization notice.
7. In the “Organization notice” field, type the DoD banner found in the VulDescription.
8. If additional languages are required, click "Add an additional language" to post the organization notice in more languages.
9. If you post the organization notice in more than one language, select the Default language option below one of the messages to make it the default language.
10. Click "Save".
11. Assign the organization notice to all applicable device profiles.

Create a device profile:
1. On the menu bar, click "Policies and Profiles".
2. Click "+" beside "Device".
3. Type a name and description for the profile. Each device profile must have a unique name.
4. Click "BlackBerry".
5. In the “Assign organization notice” drop-down list, select the organization notice that you want to display on devices.
6. Click "Add".

Add the Device Profile to all applicable groups:
1. On the menu bar, click "GROUPS".
2. For all applicable groups, select the group from the group list.
3. Click "Settings" tab.
4. Click "+" beside "IT policy and profiles".
5. Select "Device" from menu.
6. Select the appropriate Device profile from the drop down menu".
7. Click "Assign".'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66351r3_chk'
  tag severity: 'low'
  tag gid: 'V-65697'
  tag rid: 'SV-80187r1_rule'
  tag stig_id: 'BB10-3X-000240'
  tag gtitle: 'PP-MDF-201015'
  tag fix_id: 'F-71739r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000366']
  tag nist: ['AC-8 a', 'CM-6 b']
end
