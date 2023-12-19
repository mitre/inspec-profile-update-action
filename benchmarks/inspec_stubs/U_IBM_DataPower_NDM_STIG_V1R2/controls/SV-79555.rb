control 'SV-79555' do
  title 'The DataPower Gateway must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
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
  desc 'fix', %q(Get the User Interface (UI) Configuration Template File from the IBM DataPower Gateway website >> Copy the template to a new text file on the local operating system named "ui-customization.xml".

Upload the User Interface Customization Template: Privileged account user log on to default domain >> Control Panel >> File Management >> Click "local:" >> Click "Actions..." Link corresponding to "local:" >> Click "Upload Files" >> Click "Browse" button >> Select the previously saved "ui-customization.xml" file from the local operating system >> Click "Open" >> Click the "Upload" button" >> Click the "Continue" button.

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
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65691r1_chk'
  tag severity: 'low'
  tag gid: 'V-65065'
  tag rid: 'SV-79555r1_rule'
  tag stig_id: 'WSDP-NM-000016'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-71005r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
