control 'SV-82525' do
  title 'The A10 Networks ADC must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', %q(Observe someone logging onto the device. 

If the device does not present a DoD-approved banner, this is a finding. 

For the CLI, the short form of the banner is acceptable.

Use the following verbiage for applications that can accommodate banners of 1300 characters:
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'fix', %q(The following command sets the banner to be displayed when an administrator logs onto the CLI:
banner login multi-line 
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. I've read and consent to the terms in the IS User Agreement."

Note: The " is the end-marker that delineates the banner text.

The following process adds a Logon Banner to CLI and a Web Logon Message:
In the WebGUI, navigate to Config Mode >> System >> Settings >> Terminal >> Banner
For Banner Type: Select multi-line.
Enter the approved text (short version) in the Logon Banner: text entry area.
Enter the approved text (either version) in the Web Logon Message: text entry area.

Use the following verbiage for applications that can accommodate banners of 1300 characters:
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't."

Select the "OK" box at the bottom of the screen.)
  impact 0.3
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68595r1_chk'
  tag severity: 'low'
  tag gid: 'V-68035'
  tag rid: 'SV-82525r1_rule'
  tag stig_id: 'AADC-NM-000016'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-74151r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
