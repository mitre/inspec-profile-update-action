control 'SV-251661' do
  title 'Splunk Enterprise must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the server.'
  desc %q(Display of the DOD-approved use notification before granting access to the application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

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
  desc 'check', 'This check is performed on the machine used as a search head, which may be a separate machine in a distributed environment.

If the instance being reviewed is not used as a search head, this check in N/A.

Verify that the Standard Mandatory DOD Notice and Consent Banner appears before being granted access to Splunk Enterprise.

If the Standard Mandatory DOD Notice and Consent Banner is not presented, this is a finding.'
  desc 'fix', 'This configuration is performed on the machine used as a search head, which may be a separate machine in a distributed environment.

Configure Splunk Enterprise to display the Mandatory DOD Notice and Consent Banner by modifying the web.conf file.

Add/modify the line: 
login_content = <script>function DoDBanner() {alert("You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\\n-At any time, the USG may inspect and seize data stored on this IS.\\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.");}DoDBanner();</script>

The string in the above line will be the text of the DOD consent banner.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55099r918483_chk'
  tag severity: 'low'
  tag gid: 'V-251661'
  tag rid: 'SV-251661r918485_rule'
  tag stig_id: 'SPLK-CL-000080'
  tag gtitle: 'SRG-APP-000068-AU-000035'
  tag fix_id: 'F-55053r918484_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
