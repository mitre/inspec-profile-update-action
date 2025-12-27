control 'SV-230089' do
  title 'The Motorola Android Pie must be configured to display the DoD advisory warning message at startup or each time the user unlocks the device.'
  desc %q(Android Pie is required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. Required banners help ensure that DoD can audit and monitor the activities of mobile device users without legal restriction.

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

The Administrator must configure the banner text exactly as written without any changes.

SFR ID: FMT_SMF_EXT.1.1 #36)
  desc 'check', 'The DoD warning banner can be displayed by either of the following methods (required text is found in the Vulnerability Discussion):

1. By placing the DoD warning banner text in the user agreement signed by each Motorola Android device user (preferred method).
2. By configuring the warning banner text on the MDM console and installing the banner on each managed mobile device.

Determine which method is used at the Motorola Android device site and follow the appropriate validation procedure below.

Validation Procedure for Method #1: 
Review the signed user agreements for several Motorola Android device users and verify the agreement includes the required DoD warning banner text.

Validation Procedure for Method #2:
On the MDM console, ensure "Lock Screen Message" is set and the appropriate banner text is included.

If, for Method #1, the required warning banner text is not on all signed user agreements reviewed, or for Method #2, the MDM console device policy is not set to display a warning banner with the appropriate designated wording or on the Android Pie device, the device policy is not set to display a warning banner with the appropriate designated wording, this is a finding.'
  desc 'fix', 'Configure the DoD warning banner by either of the following methods (required text is found in the Vulnerability Discussion):

1. By placing the DoD warning banner text in the user agreement signed by each Motorola Android device user (preferred method).
2. By configuring the warning banner text on the MDM console and installing the banner on each managed mobile device.

On the MDM console: 
Enable "Lock Screen Message" and enter the banner text.'
  impact 0.3
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32404r538263_chk'
  tag severity: 'low'
  tag gid: 'V-230089'
  tag rid: 'SV-230089r569708_rule'
  tag stig_id: 'MOTO-09-003400'
  tag gtitle: 'GOOG-09-003400'
  tag fix_id: 'F-32382r538264_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
