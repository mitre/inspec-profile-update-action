control 'SV-90593' do
  title 'CounterACT, when providing user access control intermediary services, must display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network.'
  desc 'Display of a standardized and approved use notification before granting access to the network ensures privacy and security notification verbiage used is consistent with DoD requirements.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist, for example, with CounterACT guest access function. This requirement applies to network elements that have the concept of a user account and have the logon function residing on the network element. This requirement is not for access to the device itself, such as with system administrators of CounterACT, but rather is related to the network access control function provided to the users.

The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for network elements that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'check', 'If CounterACT does not provide user access control intermediary services, this is not applicable.

Verify CounterACT displays the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network. 

1. Log on to CounterACT’s Administrator UI. 
2. Go to Tools >> Options >> User Console and Options >> Password and Logon.
3. Enable the "Display this Notice and Consent Message after login" and complete the provided text input area to have the Standard Mandatory DoD and Consent Banner before granting access to the device. This banner must include the following text: 
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 

If CounterACT does not display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network, this is a finding.'
  desc 'fix', 'If user network access control intermediary services are provided, configure CounterACT to display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network. 

1. Log in to CounterACT’s Administrator UI. 
2. Go to Tools >> Options >> User Console and Options >> Password and Logon.
3. Enable the "Display this Notice and Consent Message after login" and complete the provided text input area to have the Standard Mandatory DoD and Consent Banner before granting access to the device. This banner must include the following text: 
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75913'
  tag rid: 'SV-90593r1_rule'
  tag stig_id: 'CACT-AG-000001'
  tag gtitle: 'SRG-NET-000041-ALG-000022'
  tag fix_id: 'F-82543r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
