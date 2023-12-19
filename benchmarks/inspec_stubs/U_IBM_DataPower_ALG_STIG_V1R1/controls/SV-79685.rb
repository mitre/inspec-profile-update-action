control 'SV-79685' do
  title 'The DataPower Gateway providing user access control intermediary services must display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network.'
  desc %q(Display of a standardized and approved use notification before granting access to the network ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. This requirement applies to network elements that have the concept of a user account and have the logon function residing on the network element.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for network elements that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't."

This policy only applies to ALGs (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.)
  desc 'check', 'Privileged user opens browser and navigates to the DataPower logon page.

Confirm that the logon page displays the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the standard banner is not displayed, this is a finding.'
  desc 'fix', %q(Copy the User Interface (UI) Configuration Template to a new text file on the local operating system named "ui-customization.xml". Content: <User-Interface
xmlns="http://www.datapower.com/schemas/user-interface/1.0">
 
<!-- Markup for the prompt extension to command line interface >>
 <CustomPrompt>%s</CustomPrompt>

<!-- Markup for custom messages for the WebGUI interface >>
<MarkupBanner type="pre-login" foreground-color="red" background-color="blue">
WebGUI pre-login message
</MarkupBanner>
<MarkupBanner type="post-login" foreground-color="blue" background-color="yellow">
WebGUI post-login pop up message
</MarkupBanner>
<MarkupBanner type="system-banner" location="header" foreground-color="green"
background-color="red">
WebGUI system message - header
</MarkupBanner>
<MarkupBanner type="system-banner" location="footer" foreground-color="blue"
background-color="yellow">
WebGUI system message - footer
</MarkupBanner>
 
 <!-- If the following markup was outside of comments, the file would not conform to the schema. Cannot define multiple system messages as the header or footer. >>
<MarkupBanner type="system-banner">
WebGUI system message - header and footer
</MarkupBanner>

<!-- Markup for custom messages for the command line interface >>
<TextBanner type="pre-login">
Command line pre-login message
</TextBanner>
<TextBanner type="post-login">
Command line post-login message
</TextBanner>
<TextBanner type="system-banner">
Command line system message
</TextBanner>
</User-Interface>

Upload the User Interface Customization Template: Privileged account user log on to default domain >> Control Panel >> File Management >> Click "local:" >> Click "Actions..." link corresponding to "local:" >> Click "Upload Files" >> Click "Browse" button >> Select the previously saved "ui-customization.xml" file from the local operating system >> Click "Open" >> Click the "Upload" button" >> Click the "Continue" button.

Edit the "ui-customization.xml" file: Click "refresh page" >> Click "local:" >> Click the "Edit" link corresponding to "ui-customization.xml" >> Click the "Edit" button >> Locate the XML Stanza named "MarkupBanner" and 'type="pre-login"' >> Replace the text "WebGUI pre-login message" with the text of the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

>> Locate the XML Stanza named "TextBanner" and 'type="pre-login"' >> Replace the text "Command line pre-login message" with the text of the Standard Mandatory DoD Notice and Consent Banner: "I've read & consent to terms in IS user agreem't." >> Click the "Submit" button.

Configure the IBM DataPower Gateway to use the customized User Interface Customization file: Administration >> Device >> System Settings >> Scroll to "Custom user interface file" section at the bottom of the page and select "ui-customization.xml" from the drop-down list >> Scroll to top of the page >> Click "Apply" >> Click "Save Configuration".

Log out of the appliance.)
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65823r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65195'
  tag rid: 'SV-79685r1_rule'
  tag stig_id: 'WSDP-AG-000011'
  tag gtitle: 'SRG-NET-000041-ALG-000022'
  tag fix_id: 'F-71135r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
