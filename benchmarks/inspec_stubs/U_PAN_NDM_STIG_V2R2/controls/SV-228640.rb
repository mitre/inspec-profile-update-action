control 'SV-228640' do
  title 'The Palo Alto Networks security platform must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', %q(View the logon screen of the Palo Alto Networks security platform.  A white text box at the bottom of the screen will contain the configured text.
If it is blank (there is no white text box) or the wording is not one of the approved banners, this is a finding.

This is the approved verbiage for applications that can accommodate banners of 1300 characters:
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't.")
  desc 'fix', 'Go to Device >> Setup >> Management >> General Settings ("Edit" icon) >> Login Banner
Type in the required text
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30875r513525_chk'
  tag severity: 'low'
  tag gid: 'V-228640'
  tag rid: 'SV-228640r513527_rule'
  tag stig_id: 'PANW-NM-000016'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-30852r513526_fix'
  tag 'documentable'
  tag legacy: ['SV-77197', 'V-62707']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
