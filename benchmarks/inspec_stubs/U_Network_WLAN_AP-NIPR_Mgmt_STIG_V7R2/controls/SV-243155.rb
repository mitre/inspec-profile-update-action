control 'SV-243155' do
  title 'The network device must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc %q(All network devices must present a DoD-approved warning banner prior to a system administrator logging on. The banner should warn any unauthorized user not to proceed. It also should provide clear and unequivocal notice to both authorized and unauthorized personnel that access to the device is subject to monitoring to detect unauthorized usage. Failure to display the required logon warning banner prior to logon attempts limits DoD's ability to prosecute unauthorized access and also presents the potential for criminal and civil liability for systems administrators and information systems managers. In addition, DISA's ability to monitor the device's usage is limited unless a proper warning banner is displayed.

DoD CIO has issued new, mandatory policy standardizing the wording of "notice and consent" banners and matching user agreements for all Secret and below DoD information systems, including stand-alone systems by releasing DoD CIO Memo, "Policy on Use of Department of Defense (DoD) Information Systems Standard Consent Banner and User Agreement", dated 9 May 2008. The banner is mandatory and deviations are not permitted except as authorized in writing by the Deputy Assistant Secretary of Defense for Information and Identity Assurance. Implementation of this banner verbiage is further directed to all DoD components for all DoD assets via USCYBERCOM CTO 08-008A.)
  desc 'check', %q(Review the device configuration or request that the administrator log on to the device and observe the terminal. 

Verify either Option A or Option B (for systems with character limitations) of the Standard Mandatory DoD Notice and Consent Banner is displayed at logon. The required banner verbiage follows and must be displayed verbatim:

Option A

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

Option B

If the system is incapable of displaying the required banner verbiage due to its size, a smaller banner must be used. The mandatory verbiage follows: "I've read & consent to terms in IS user agreem't."

If the device configuration does not have a logon banner as stated above, this is a finding.)
  desc 'fix', %q(Configure all management interfaces to the network device to display the DoD-mandated warning banner verbiage at logon regardless of the means of connection or communication. The required banner verbiage that must be displayed verbatim as follows:

Option A

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

Option B

If the system is incapable of displaying the required banner verbiage due to its size, a smaller banner must be used. The mandatory verbiage follows: "I've read & consent to terms in IS user agreem't.")
  impact 0.5
  ref 'DPMS Target Network WLAN AP-NIPR Mgmt'
  tag check_id: 'C-46430r719918_chk'
  tag severity: 'medium'
  tag gid: 'V-243155'
  tag rid: 'SV-243155r879547_rule'
  tag stig_id: 'WLAN-ND-000400'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-46387r719919_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
