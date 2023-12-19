control 'SV-217733' do
  title 'Samsung Android must be configured to display the DoD advisory warning message at startup or each time the user unlocks the device.'
  desc %q(The mobile operating system is required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. Required banners help ensure that DoD can audit and monitor the activities of mobile device users without legal restriction. 

System use notification messages can be displayed when individuals first access or unlock the mobile device. The banner must be implemented as a "click-through" banner at device unlock (to the extent permitted by the operating system). A "click-through" banner prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK." 

The approved DoD text must be used exactly as required in the KS referenced in DoDI 8500.01. For devices accommodating banners of 1300 characters, the banner text is: 

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
  desc 'check', 'Confirm if Method #1 or Method #2 is used at the Samsung device site and follow the appropriate procedure. 

**** 

Method #1: Review the signed user agreements for several Samsung device users and verify that the agreement includes the required DoD warning banner text. 

If the required DoD warning text is not included in all reviewed signed user agreements, this is a finding. 

**** 

Method #2: This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox banner" group, verify that the "banner text" is configured with the required DoD warning banner text. 

On the Samsung Android device, verify that that after a reboot the required DoD warning banner text is displayed. 

If on the MDM console the "banner text" is not configured with the required DoD warning banner text, or after a reboot the required DoD warning banner text is not displayed on the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure the DoD warning banner by either of the following methods (required text is found in the Vulnerability Discussion): 

- Method #1: Place the DoD warning banner text in the user agreement signed by each Samsung device user. 
- Method #2: Configure Samsung Android to display the DoD-mandated warning banner text. 

Use either Method #1 (preferred method) or Method #2. 

**** 

Method #1: Include the DoD warning banner text in the user agreement that will be signed by each Samsung device user. 

**** 

Method #2: On the MDM console, for the device, in the "Knox banner" group, configure the "banner text" with the DoD-mandated warning banner text. 

Note: On some MDM consoles, the Knox banner is automatically enabled while the Samsung Android device is enrolled. In this case, the above guidance is not applicable.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18951r362347_chk'
  tag severity: 'low'
  tag gid: 'V-217733'
  tag rid: 'SV-217733r378520_rule'
  tag stig_id: 'KNOX-09-001165'
  tag gtitle: 'PP-MDF-301200'
  tag fix_id: 'F-18949r362348_fix'
  tag 'documentable'
  tag legacy: ['SV-103713', 'V-93627']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
