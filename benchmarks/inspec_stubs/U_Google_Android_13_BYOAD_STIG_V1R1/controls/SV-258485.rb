control 'SV-258485' do
  title 'Google Android 13 must be configured to display the DOD advisory warning message at startup or each time the user unlocks the Work Profile.'
  desc %q(Before granting access to the system, the mobile operating system is required to display the DOD-approved system use notification message or banner that provides privacy and security notices consistent with applicable Federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. Required banners help ensure that DOD can audit and monitor the activities of mobile device users without legal restriction.

System use notification messages can be displayed when individuals first access or unlock the mobile device. The banner must be implemented as a "click-through" banner at device unlock (to the extent permitted by the operating system). A "click-through" banner prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

The approved DOD text must be used exactly as required in the Knowledge Service referenced in DODI 8500.01. For devices accommodating banners of 1300 characters, the banner text is: 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

For devices with severe character limitations, the banner text is:

I've read & consent to terms in IS user agreem't.

The administrator must configure the banner text exactly as written without any changes.

SFR ID: FMT_SMF_EXT.1.1 #36)
  desc 'check', 'The DOD warning banner can be displayed using the following method (required text is found in the Vulnerability Discussion):

By placing the DOD warning banner text in the user agreement signed by each managed Android 13 device user (preferred method).

Note: It is not possible for the EMM to force a warning banner be placed on the device screen when using "work profile for employee-owned devices (BYOD)" deployment mode.

Review the signed user agreements for several Google Android 13 device users and verify the agreement includes the required DOD warning banner text.

If the required warning banner text is not on all signed user agreements reviewed, this is a finding.'
  desc 'fix', 'Configure the DOD warning banner by the following method (required text is found in the Vulnerability Discussion):

By placing the DOD warning banner text in the user agreement signed by each Google Android 13 device user (preferred method).

Note: It is not possible for the EMM to force a warning banner be placed on the device screen when using "work profile for employee-owned devices (BYOD)" deployment mode.'
  impact 0.3
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62225r929269_chk'
  tag severity: 'low'
  tag gid: 'V-258485'
  tag rid: 'SV-258485r929271_rule'
  tag stig_id: 'GOOG-13-707700'
  tag gtitle: 'PP-MDF-333160'
  tag fix_id: 'F-62134r929270_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
