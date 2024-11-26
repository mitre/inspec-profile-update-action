control 'SV-256074' do
  title 'The Riverbed NetProfiler must be configured to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DOD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Check under "Log-in Settings". 

Verify the following verbiage is used exactly as displayed with spacing and syntax as depicted in DTM-08-060:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the "Log-in splash screen display" is not set to display the Standard Mandatory DOD Notice and Consent Banner on the login screen exactly in the format required by DOD, this is a finding.'
  desc 'fix', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Under "Log-in Settings" on the "Log-in splash screen display", use the drop-down menu to select "Show until Acknowledged".

Click the browse button beside "Upload new log-in splash screen" to select the banner file.

Click "OK" to save the settings.

NOTE: The banner file can only be uploaded in JPG format.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59748r882728_chk'
  tag severity: 'medium'
  tag gid: 'V-256074'
  tag rid: 'SV-256074r882730_rule'
  tag stig_id: 'RINP-DM-000009'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-59691r882729_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
