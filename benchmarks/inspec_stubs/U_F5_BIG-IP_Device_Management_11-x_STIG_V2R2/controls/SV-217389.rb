control 'SV-217389' do
  title 'The BIG-IP appliance must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', %q(Verify the BIG-IP appliance is configured to present a DoD-approved banner formatted in accordance with DTM-08-060. 

Navigate to the BIG-IP System manager >> System >> Preferences.

Verify "Show The Security Banner On The Login Screen" is Enabled.

Review the "Security Banner Text To Show On The Login Screen" under the "Security Settings" section for the following verbiage:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't."

If such a banner is not presented, this is a finding.)
  desc 'fix', 'Configure the BIG-IP appliance to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18614r290721_chk'
  tag severity: 'low'
  tag gid: 'V-217389'
  tag rid: 'SV-217389r879547_rule'
  tag stig_id: 'F5BI-DM-000033'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-18612r290722_fix'
  tag 'documentable'
  tag legacy: ['SV-74671', 'V-60241']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
