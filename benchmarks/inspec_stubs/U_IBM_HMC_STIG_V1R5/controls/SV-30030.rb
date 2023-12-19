control 'SV-30030' do
  title 'The Department of Defense (DoD) logon banner must be displayed prior to any login attempt.'
  desc 'Failure to display the required DoD logon banner prior to a login attempt may void legal proceedings resulting from unauthorized access to system resources and may leave the SA, IAO, IAM, and Installation Commander open to legal proceedings for not advising users that keystrokes are being audited.'
  desc 'check', 'Have the reviewer verify that the logon banner reads as follows:on the Create Welcome Text  window: 



STANDARD MANDATORY DOD NOTICE AND CONSENT BANNER

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

If any item in above is untrue, this is a FINDING.'
  desc 'fix', 'The System Administrator will update the logon banner by going to the Create Welcome Text Task to read as follows: 

STANDARD MANDATORY DOD NOTICE AND CONSENT BANNER

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24362'
  tag rid: 'SV-30030r2_rule'
  tag stig_id: 'HMC0160'
  tag gtitle: 'HMC0160'
  tag fix_id: 'F-26749r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Systems Programmer']
  tag ia_controls: 'ECWM-1'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
