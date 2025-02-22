control 'SV-89581' do
  title 'The MQ Appliance messaging server management interface must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  desc 'Messaging servers are required to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system management interface, providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance that states that: 

(i) users are accessing a U.S. Government information system; 
(ii) system usage may be monitored, recorded, and subject to audit; 
(iii) unauthorized use of the system is prohibited and subject to criminal and civil penalties; and 
(iv) the use of the system indicates consent to monitoring and recording.

System use notification messages can be implemented in the form of warning banners displayed when individuals log on to the information system. 

System use notification is intended only for information system access including an interactive logon interface with a human user, and is not required when an interactive interface does not exist. 

Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'check', %q(Using a browser, navigate to the MQ Appliance logon page as a privileged user. 

Verify the logon page displays the Standard Mandatory DoD Notice and Consent Banner:

For the WebGUI, the banner must read:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
Logging in signifies acceptance of this agreement."

For the SSH CLI, the banner must read:

"I've read & consent to terms in IS user agreem't.
Logging in signifies acceptance of this agreement."

If the standard banner is not displayed in both the WebGUI and CLI interfaces, this is a finding.)
  desc 'fix', %q(The custom banner must be set up as follows:
1. Log on to the WebGUI as a privileged user.
2. Click on the Administration (gear) icon.
3. Under Main, click on File Management.
4. Open the "Store" directory.
5. Scroll down to the file, "dp-user-interface-demo.xml".
6. Click in the box to the left of the file name.
7. At the top of the page, click on the Copy button.
8. Select "local:" as the New Directory Name.
9. Enter a New File Name e.g., "ui-customization.xml".
10. Click Confirm copy.
11. Click Continue.
12. Edit the "ui-customization.xml" file. 
13. Refresh the browser page.
14. Click "local:".
15. Click the "Edit" link to the right of "ui-customization.xml".
16. Click the "Edit" button.
17. Locate the XML Stanza named "MarkupBanner".
18. 'type="pre-login"'. 
19. Replace the existing text with the text of the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
Logging in signifies acceptance of this agreement."

20. Locate the XML Stanza named "TextBanner".
21. 'type="pre-login"'
22. Replace the existing text with the text of the Standard Mandatory DoD Notice and Consent Banner: "I've read and consent to terms in IS user agreement.
Logging in signifies acceptance of this agreement." 
23. Click the "Submit" button.
24. Configure the MQ Appliance to use the customized User Interface Customization file: In the WebGUI, click on Gear icon (Administration) then select Device >> System Settings.
25. Scroll to "Custom user interface file" section at the bottom of the page and select the local:/// directory then the "ui-customization.xml" from the drop-down list.
26. Scroll to top of the page.
27. Click "Apply". 
28. Click "Save Configuration".

Log off of the appliance.)
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74907'
  tag rid: 'SV-89581r1_rule'
  tag stig_id: 'MQMH-AS-001100'
  tag gtitle: 'SRG-APP-000068-AS-000035'
  tag fix_id: 'F-81523r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
