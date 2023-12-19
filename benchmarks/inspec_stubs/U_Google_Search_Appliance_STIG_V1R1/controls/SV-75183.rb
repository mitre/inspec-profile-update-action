control 'SV-75183' do
  title 'Google Search Appliances must display an approved system use notification message or banner before granting access to the system.'
  desc 'Applications must display an approved system use notification message or banner before granting access to the system.  

The banner must be formatted in accordance with the DoD policy "Use of DoD Information Systems - Standard Consent and User Agreement".  The message banner shall provide privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance and shall state that:
 
(i) users are accessing a U.S. Government information system; 
(ii) system usage may be monitored, recorded, and is subject to audit; 
(iii) unauthorized use of the system is prohibited and subject to criminal and civil penalties;
(iv) the use of the system indicates consent to monitoring and recording;
(v) in the notice given to public users of the information system, shall provide a description of the authorized uses of the system.

System use notification messages are implemented in the form of warning banners displayed when individuals log in to the information system. System use notification is intended only for information system access including an interactive login interface with a human user and is not intended to require notification when an interactive interface does not exist. 

The banner shall state:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided
for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the
following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes
including, but not limited to, penetration testing, COMSEC monitoring, network
operations and defense, personnel misconduct (PM), law enforcement (LE), and
counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine
monitoring, interception, and search, and may be disclosed or used for any USG authorized
purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect
USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI
investigative searching or monitoring of the content of privileged communications, or
work product, related to personal representation or services by attorneys,
psychotherapists, or clergy, and their assistants. Such communications and work product
are private and confidential. See User Agreement for details."'
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
  tag check_id: 'C-61677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60731'
  tag rid: 'SV-75183r1_rule'
  tag stig_id: 'GSAP-00-000165'
  tag gtitle: 'SRG-APP-000070'
  tag fix_id: 'F-66411r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
