control 'SV-89605' do
  title 'The MQ Appliance network device must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the MQ Appliance network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 

System use notifications are required only for access via logon interfaces with human users.'
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
  desc 'fix', %q(Log on to the WebGUI as a privileged user. 

The custom banner must be set up as follows: 

1. Click on the Administration (gear) icon. 
2. Under Main, click on File Management. 
3. Open the "Store" directory. 
4. Scroll down to the file "ui-customization.xml". 
5. Click in the box to the left of the file name. 
6. At the top of the page, click on the Copy button. 
7. Select "local:" as the New Directory Name. 
8. Enter a New File Name, e.g., "ui-customization.xml". 
9. Click Confirm copy. 
10. Click Continue. 
11. Edit the "ui-customization.xml" file. 
12. Refresh the browser page. 
13. Click "local:". 
14. Click the "Edit" link to the right of "ui-customization.xml". 
15. Click the "Edit" button. 
16. Locate the XML Stanza named "MarkupBanner". 
17. 'type="pre-login"'. 
18. Replace the text "WebGUI pre-login message" with the text of the Standard Mandatory DoD Notice and Consent Banner: 

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 

By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. 
Logging in signifies acceptance of this agreement." 

19. Locate the XML Stanza named "TextBanner". 
20. 'type="pre-login"'. 
21. Replace the text "Command line pre-login message" with the text of the Standard Mandatory DoD Notice and Consent Banner: "I've read & consent to terms in IS user agreem't. 
Logging in signifies acceptance of this agreement." 
22. Click the "Submit" button. 

Configure the MQ Appliance to use the customized User Interface Customization file: 

In the WebGUI, click on the Gear icon (Administration) and then select Device >> System Settings. 

Scroll to "Custom user interface file" section at the bottom of the page and select the local:/// directory and then the "ui-customization.xml" from the drop-down list. 

Scroll to the top of the page. 
Click "Apply”. 
Click "Save Configuration". 

Log out of the appliance.)
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74931'
  tag rid: 'SV-89605r1_rule'
  tag stig_id: 'MQMH-ND-000160'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-81547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
