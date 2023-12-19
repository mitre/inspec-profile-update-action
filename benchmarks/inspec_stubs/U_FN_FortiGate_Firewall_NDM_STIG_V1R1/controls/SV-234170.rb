control 'SV-234170' do
  title 'The FortiGate device must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the administrator prior to the device allowing the administrator access to the network device. This ensures the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement.

In the case of CLI access using a terminal client, entering the username and password when the banner is presented is considered an explicit action of acknowledgement. Entering the username, viewing the banner, then entering the password is also acceptable.'
  desc 'check', '1. Attempt to access the FortiGate device using HTTPS URL.
2. Verify Standard Mandatory DoD Notice and Consent Banner is displayed and retained on the screen.
3. Verify a user has to explicitly ACCEPT the banner before to log on for further access.

If Standard Mandatory DoD Notice and Consent Banner is not retained, and a user is not forced to ACCEPT the banner to log on for further access, this is a finding.

And, 

1. Attempt to login to the FortiGate via SSH:
2. Enter username.
3. Verify the Standard Mandatory DoD Notice and Consent Banner before prompting to enter a password.

If Standard Mandatory DoD Notice and Consent Banner is not retained before entering the password to log on for further access, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system global
     #    set pre-login-banner enable
     # end
     #    config system replacemsg admin pre_admin-disclaimer-text 
     #    set buffer "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

          By using this IS (which includes any device attached to this IS), you consent to the following conditions:
          The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
          At any time, the USG may inspect and seize data stored on this IS.
          Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
          This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
          Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
         # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37355r611697_chk'
  tag severity: 'medium'
  tag gid: 'V-234170'
  tag rid: 'SV-234170r628777_rule'
  tag stig_id: 'FGFW-ND-000055'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-37320r611698_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
