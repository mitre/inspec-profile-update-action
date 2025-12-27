control 'SV-90883' do
  title 'CounterACT must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to CounterACT ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', '1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Enable "Display this Notice and Consent Message after login" and complete the provided text input area to have the Standard Mandatory DoD and Consent Banner appear before granting access to the device. This banner must include the following text:

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details".

If this is not present, this is a finding.'
  desc 'fix', '1. Log on to the CounterACT Administrator UI.
2. Select Tools >> Options >> User Console and Options >> Password and Login.
3. Enable "Display this Notice and Consent Message after login" and complete the provided text input area to have the Standard Mandatory DoD and Consent Banner before granting access to the device. This banner must include the following text:

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details".

4. Select "Apply" to save the settings.'
  impact 0.3
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75881r1_chk'
  tag severity: 'low'
  tag gid: 'V-76195'
  tag rid: 'SV-90883r1_rule'
  tag stig_id: 'CACT-NM-000021'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-82833r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
