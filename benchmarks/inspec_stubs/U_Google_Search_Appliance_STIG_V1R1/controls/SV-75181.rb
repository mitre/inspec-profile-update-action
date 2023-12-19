control 'SV-75181' do
  title 'The Google Search Appliance must retain the notification message or banner on the screen until users take explicit actions to logon to or further access.'
  desc 'To establish acceptance of system usage policy, a click-through banner at application logon is required. The banner must prevent further activity on the application unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK". The text of this banner should be customizable in the event of future user agreement changes.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "Login Terms".

If "Enable Login Terms Banner" is checked, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

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
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60729'
  tag rid: 'SV-75181r1_rule'
  tag stig_id: 'GSAP-00-000160'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-66409r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
