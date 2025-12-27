control 'SV-231026' do
  title 'Samsung Android must be configured to display the DoD advisory warning message at startup or each time the user unlocks the device.'
  desc %q(The mobile operating system is required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. Required banners help ensure that DoD can audit and monitor the activities of mobile device users without legal restriction.

System use notification messages can be displayed when individuals first access or unlock the mobile device. The banner must be implemented as a "click-through" banner at device unlock (to the extent permitted by the operating system). A "click-through" banner prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

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
  desc 'check', 'Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Validation Procedure for Method #1: Place the DoD warning banner in the user agreement signed by each Samsung Android device user (preferred method).

Review the signed user agreements for several Samsung Android device users and verify that the agreement includes the required DoD warning banner text.

****

Validation Procedure for Method #2: Configure the warning banner text in the KPE Reboot Banner on each managed mobile device.

On the management tool, in the device Banner section, verify that "Banner Text" is set to the DoD-managed warning banner text.

On the Samsung Android device, verify that after a reboot the required DoD warning banner text is displayed.

****

If the warning text has not been placed in the signed user agreement, or if on the management tool "Banner Text" is not set to the DoD-mandated warning banner text, or on the Samsung Android device the required DoD warning banner text is not displayed after a reboot, this is a finding.'
  desc 'fix', 'Configure the DoD warning banner by either of the following methods (required text is found in the Discussion):

Method #1: Place the DoD warning banner in the user agreement signed by each Samsung Android device user (preferred method).

****

Method #2: Configure the warning banner text in the KPE Reboot Banner on each managed mobile device.

On the management tool, in the device Banner section, set "Banner Text" to the DoD-managed warning banner text.'
  impact 0.3
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33956r592692_chk'
  tag severity: 'low'
  tag gid: 'V-231026'
  tag rid: 'SV-231026r608683_rule'
  tag stig_id: 'KNOX-11-006400'
  tag gtitle: 'PP-MDF-301200'
  tag fix_id: 'F-33929r592693_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
