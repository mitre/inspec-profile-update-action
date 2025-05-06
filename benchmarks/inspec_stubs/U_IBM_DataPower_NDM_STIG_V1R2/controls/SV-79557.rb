control 'SV-79557' do
  title 'The DataPower Gateway must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the administrator prior to allowing the administrator access to the network device. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'WebGUI logon page: If DataPower does not retain the banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access, this is a finding.

CLI logon: If DataPower does not display the banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access, this is a finding.'
  desc 'fix', %q(Get the User Interface (UI) Configuration Template File from the IBM DataPower Gateway online website >> Copy the template to a new text file on the local operating system named "ui-customization.xml"

Upload the User Interface Customization Template: Privileged account user log on to default domain >> Control Panel >> File Management >> Click "local:" >> Click "Actions..." link corresponding to "local:" >> Click "Upload Files" >> Click "Browse" button >> Select the previously saved "ui-customization.xml" file from the local operating system >> Click "Open" >> Click the "Upload" button" >> Click the "Continue" button.

Edit the "ui-customization.xml" file: Click "refresh page" >> Click "local:" >> Click the "Edit" link corresponding to "ui-customization.xml" >> Click the "Edit" button >> Locate the XML Stanza named "MarkupBanner" and 'type="pre-logon"' >> Replace the text "WebGUI pre-logon message" with the text of the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

>> Locate the XML Stanza named "TextBanner" and 'type="pre-logon"' >> replace the text "Command line pre-logon message" with the text of the Standard Mandatory DoD Notice and Consent Banner: "I've read & consent to terms in IS user agreem't." >> Click the "Submit" button.

Configure the IBM DataPower Gateway to use the customized User Interface Customization file: Administration >> Device >> System Settings >> Scroll to "Custom user interface file" section at the bottom of the page and select "ui-customization.xml" from the drop-down list >> Scroll to top of the page >> Click "Apply" >> Click "Save Configuration".

Log out of the appliance.)
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65067'
  tag rid: 'SV-79557r1_rule'
  tag stig_id: 'WSDP-NM-000017'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-71007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
