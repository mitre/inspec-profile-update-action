control 'SV-14593' do
  title 'All users of mobile devices or wireless devices must sign a user agreement before the mobile or wireless device is issued to the user and the user agreement used at the site must include required content.'
  desc 'Lack of user training and understanding of responsibilities to safeguard wireless technology is a significant vulnerability to the enclave. Once policies are established, users must be trained to these requirements or the risk to the network remains.

User agreements are particularly important for mobile and remote users since there is a high risk of loss, theft, or compromise. Thus, this signed agreement is a good best practice to help ensure the site is confirming the user is aware of the risks and proper procedures.'
  desc 'check', %q(Additional Policy Requirements:

The user agreements must include DAA authorized tasks for the mobile device and relevant security requirements, including, but not limited to, the following:

1. DoD CIO Memorandum, “Policy on Use of Department of Defense (DoD) Information Systems Standard Consent Banner and User Agreement,” 9 May 2008 directs the following content will be included in a site User Agreement:

STANDARD MANDATORY NOTICE AND CONSENT PROVISION FOR ALL DOD INFORMATION SYSTEM USER AGREEMENTS

By signing this document, you acknowledge and consent that when you access
Department of Defense (DoD) information systems:
- You are accessing a U.S. Government (USG) information system (IS) (which includes any device attached to this information system) that is provided for U.S. Government authorized use only.
- You consent to the following conditions:
o The U.S. Government routinely intercepts and monitors communications on this information system for purposes including, but not limited to, penetration testing, communications security (COMSEC) monitoring, network operations and defense, personal misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
o At any time, the U.S. Government may inspect and seize data stored on this information system.
o Communications using, or data stored on, this information system are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any U.S. Government-authorized purpose.
o This information system includes security measures (e.g., authentication and access controls) to protect U.S. Government interests--not for your personal benefit or privacy.
o Notwithstanding the above, using an information system does not constitute consent to personnel misconduct, law enforcement, or counterintelligence investigative searching or monitoring of the content of privileged communications or data (including work product) that are related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Under these circumstances, such communications and work product are private and confidential, as further explained below:
- Nothing in this User Agreement shall be interpreted to limit the user's consent to, or in any other way restrict or affect, any U.S. Government actions for purposes of network administration, operation, protection, or defense, or for communications security. This includes all communications and data on an information system, regardless of any applicable privilege or confidentiality.
- The user consents to interception/capture and seizure of ALL communications and data for any authorized purpose (including personal misconduct, law enforcement, or counterintelligence investigation). However, consent to interception/capture or seizure of communications and data is not consent to the use of privileged communications or data for personnel misconduct, law enforcement, or counterintelligence investigation against any party and does not negate any applicable privilege or confidentiality that otherwise applies.
- Whether any particular communication or data qualifies for the protection of a privilege, or is covered by a duty of confidentiality, is determined in accordance with established legal standards and DoD policy. Users are strongly encouraged to seek personal legal counsel on such matters prior to using an information system if the user intends to rely on the protections of a privilege or confidentiality.
- Users should take reasonable steps to identify such communications or data that the user asserts are protected by any such privilege or confidentiality. However, the user's identification or assertion of a privilege or confidentiality is not sufficient to create such protection where none exists under established legal standards and DoD policy.
- A user's failure to take reasonable steps to identify such communications or data as privileged or confidential does not waive the privilege or confidentiality if such protections otherwise exist under established legal standards and DoD policy. However, in such cases the U.S. Government is authorized to take reasonable actions to identify such communication or data as being subject to a privilege or confidentiality, and such actions do not negate any applicable privilege or confidentiality.
- These conditions preserve the confidentiality of the communication or data, and the legal protections regarding the use and disclosure of privileged information, and thus such communications and data are private and confidential. Further, the U.S. Government shall take all reasonable measures to protect the content of captured/seized privileged communications and data to ensure they are appropriately protected.
o In cases when the user has consented to content searching or monitoring of communications or data for personnel misconduct, law enforcement, or counterintelligence investigative searching, (i.e., for all communications and data other than privileged communications or data that are related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants), the U.S. Government may, solely at its discretion and in accordance with DoD policy, elect to apply a privilege or other restriction on the U.S. Government's otherwise-authorized use or disclosure of such information.
o All of the above conditions apply regardless of whether the access or use of an information system includes the display of a Notice and Consent Banner ("banner"). When a banner is used, the banner functions to remind the user of the conditions that are set forth in this User Agreement, regardless of whether the banner describes these conditions in full detail or provides a summary of such conditions, and regardless of whether the banner expressly references this User Agreement.

2. For SME PED, see the SME PED User Agreement template included with the SME PED STIG for specific requirements.

3. DoD sites are required to add the following to all site User Agreements:
- The agreement should contain the type of access required by the user (privileged, end-user, etc.).
- The agreement should contain the responsibilities, liabilities, and security measures (e.g., malicious code detection training) involved in the use of the wireless remote access device.
- Incident handling and reporting procedures will be identified along with a designated point of contact.
- The remote user can be held responsible for damage caused to a Government system or data through negligence or a willful act.
- The policy should contain general security requirements and practices, which are acknowledged and signed by the remote user.
- If classified devices are used for remote access from an alternative work site, the remote user will adhere to DoD policy in regard to facility clearances, protection, storage, distributing, etc.
- Government owned hardware and software is used for official duties only. The employee is the only individual authorized to use this equipment.
- User agrees to complete required wireless device training annually.

4. For approved smartphone and tablet devices add to all User Agreements:
- Only approved Bluetooth headsets/handsfree devices will be used.

Check Procedures:

1. Inspect a copy of the site’s user agreement.
2. Verify the user agreement has the minimum elements described in the STIG policy. 
3. Select 10 names of assigned site personnel and verify they have a signed user agreement on file for assigned wireless equipment (e.g., wireless laptop, smartphone, tablet, etc.).

Mark as a finding if site user agreements do not exist or are not compliant with the minimum requirements.

For SME PED:
- Verify the Terminal Administrator (TA) has users reaffirm their User Agreement at least once every 12 months. Review the dates that site User Agreements were signed.)
  desc 'fix', 'Implement User Agreement with required content.  Have all users sign a User Agreement.'
  impact 0.3
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-11415r3_chk'
  tag severity: 'low'
  tag gid: 'V-13982'
  tag rid: 'SV-14593r5_rule'
  tag stig_id: 'WIR0030'
  tag gtitle: 'Sign User Agreement'
  tag fix_id: 'F-23396r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'ECWN-1, PRTN-1'
end
