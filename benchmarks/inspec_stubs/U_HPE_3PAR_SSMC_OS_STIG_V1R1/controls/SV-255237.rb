control 'SV-255237' do
  title 'Any publicly accessible connection to SSMC must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system.'
  desc %q(Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DOD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'Verify that SSMC displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system by following below steps: 

1. Log on to SSMC Web Administrator console GUI as "ssmcadmin".

2. Navigate to Actions >> Preferences >> Application.

3. Check if the login banner slider is toggled to "yes" and the desired text in English is set in the textbox adjacent to the control.

If the custom banner text is not set to the Standard Mandatory DOD Notice and Consent Banner, this is a finding.'
  desc 'fix', 'Configure SSMC to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system by following below steps: 

1. Log on to SSMC Web Administrator console GUI as "ssmcadmin".

2. Navigate to Actions >> Preferences >> Application.

3. Toggle the Login banner slider to "Yes" and enter the standard DOD banner message text (Only English is supported).

4. Click "OK" to Save your changes.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58850r869859_chk'
  tag severity: 'medium'
  tag gid: 'V-255237'
  tag rid: 'SV-255237r869861_rule'
  tag stig_id: 'SSMC-OS-010000'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-58794r869860_fix'
  tag 'documentable'
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
