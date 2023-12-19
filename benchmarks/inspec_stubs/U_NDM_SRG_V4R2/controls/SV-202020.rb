control 'SV-202020' do
  title 'The network device must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', %q(Determine if the network device is configured to present a DoD-approved banner that is formatted in accordance with DTM-08-060. If such a banner is not presented, this is a finding. Use the following verbiage for applications that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
"I've read & consent to terms in IS user agreem't.")
  desc 'fix', 'Configure the network device to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2146r381590_chk'
  tag severity: 'medium'
  tag gid: 'V-202020'
  tag rid: 'SV-202020r879547_rule'
  tag stig_id: 'SRG-APP-000068-NDM-000215'
  tag gtitle: 'SRG-APP-000068'
  tag fix_id: 'F-2147r381591_fix'
  tag 'documentable'
  tag legacy: ['SV-69303', 'V-55057']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
