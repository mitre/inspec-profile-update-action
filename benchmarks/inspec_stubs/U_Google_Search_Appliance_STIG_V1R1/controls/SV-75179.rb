control 'SV-75179' do
  title 'Google Search Appliances must display an approved system use notification message or banner before granting access to the system.'
  desc %q(Applications are required to display an approved system use notification message or banner before granting access to the system providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance and states that: 

(i) users are accessing a U.S. Government information system; 
(ii) system usage may be monitored, recorded, and subject to audit; 
(iii) unauthorized use of the system is prohibited and subject to criminal and civil penalties; and 
(iv) the use of the system indicates consent to monitoring and recording.

System use notification messages can be implemented in the form of warning banners displayed when individuals log in to the information system. 

System use notification is intended only for information system access including an interactive login interface with a human user and is not intended to require notification when an interactive interface does not exist.  

Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."                                     

For Blackberries and other PDAs/PEDs with severe character limitations use the following:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "Login Terms".

If "Enable Login Terms Banner" is checked, this is not a finding.'
  desc 'fix', %q(Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "Login Terms".

Enable option "Enable Login Terms Banner".

Enter banner information.

Click Save.

Notes: 
DoD Login Banners:
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests- -not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. 

OR

I've read & consent to terms in IS user agreem't.)
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60727'
  tag rid: 'SV-75179r1_rule'
  tag stig_id: 'GSAP-00-000155'
  tag gtitle: 'SRG-APP-000068'
  tag fix_id: 'F-66407r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
