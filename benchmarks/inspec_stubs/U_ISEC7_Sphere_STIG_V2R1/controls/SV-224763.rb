control 'SV-224763' do
  title 'The ISEC7 EMM Suite must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the ISEC7 EMM Suite.'
  desc %q(Display of the DoD-approved use notification before granting access to the application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for applications that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'Log in to the ISEC7 EMM Console.
Note if the appropriate Standard mandatory DoD Notice and Consent Banner is displayed.

Alternatively, if already logged into the ISEC7 EMM Console, navigate to Administration >> User Self Service >> Page Customizations.
Verify that a Page Customization exists to display the Standard mandatory DoD Notice and Consent Banner.

If a Page Customization does not exist or it does not contain the required DoD banner, this is a finding.'
  desc 'fix', 'Login to the ISEC7 EMM Suite console.
Navigate to Administration >> User Self Service >> Page Customizations.
Enter a name for the banner page customization and select Add.
In the new window, select Edit for the English Disclaimer and paste the DoD Standard Disclaimer Warning text.
Select Confirm.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26454r461545_chk'
  tag severity: 'medium'
  tag gid: 'V-224763'
  tag rid: 'SV-224763r505933_rule'
  tag stig_id: 'ISEC-06-000200'
  tag gtitle: 'SRG-APP-000068'
  tag fix_id: 'F-26442r461546_fix'
  tag 'documentable'
  tag legacy: ['V-97389', 'SV-106493']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
