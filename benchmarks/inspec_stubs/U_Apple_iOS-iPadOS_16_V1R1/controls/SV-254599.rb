control 'SV-254599' do
  title 'Apple iOS/iPadOS 16 must be configured to display the DoD advisory warning message at startup or each time the user unlocks the device.'
  desc %q(Before granting access to the system, the mobile operating system is required to display the DoD-approved system use notification message or banner that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. Required banners help ensure that DoD can audit and monitor the activities of mobile device users without legal restriction.

System use notification messages can be displayed when individuals first access or unlock the mobile device. The banner must be implemented as a "click-through" banner at device unlock (to the extent permitted by the operating system). A "click-through" banner prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".

The approved DoD text must be used exactly as required in the Knowledge Service referenced in DoDI 8500.01. For devices accommodating banners of 1300 characters, the banner text is: 

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
  desc 'check', 'The DoD warning banner can be displayed by either of the following methods (required text is found in the Vulnerability Discussion):

1. By placing the DoD warning banner text in the user agreement signed by each iPhone and iPad user (preferred method). 
2. By creating a background picture with the relevant information and configuring that picture as the background for the lock screen via the Apple iOS/iPadOS management tool (only available for supervised devices).

Determine which method is used at the iOS device site and follow the appropriate validation procedure below.

Validation Procedure for Method #1:
Review the signed user agreements for several iOS device users and verify the agreement includes the required DoD warning banner text.

Validation Procedure for Method #2:
- In the Apple iOS/iPadOS management tool, verify a picture of the DoD warning banner text has been configured as the background for the lock screen.
- On the iOS device, verify a picture of the DoD warning banner text is shown as the background for the locked screen.

If, for Method #1, the required warning banner text is not on all signed user agreements reviewed, or for Method #2, the DoD warning banner text is not set as the locked screen background, this is a finding.'
  desc 'fix', 'Configure the DoD warning banner by either of the following methods (required text is found in the Vulnerability Discussion):

1. By placing the DoD warning banner text in the user agreement signed by each iOS device user (preferred method).

2. By creating a background picture with the relevant information and configuring that picture as the background for the lock screen via the Apple iOS/iPadOS management tool.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58210r862051_chk'
  tag severity: 'low'
  tag gid: 'V-254599'
  tag rid: 'SV-254599r862191_rule'
  tag stig_id: 'AIOS-16-008400'
  tag gtitle: 'PP-MDF-323160'
  tag fix_id: 'F-58156r862190_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
