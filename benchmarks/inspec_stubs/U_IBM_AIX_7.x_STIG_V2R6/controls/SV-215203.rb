control 'SV-215203' do
  title 'Any publically accessible connection to AIX operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  desc %q(Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'Check the herald is set to have the Standard Mandatory DoD Notice and Consent Banner:
# lssec -f /etc/security/login.cfg -s default -a herald

The above command should display the herald setting like this:
default herald="You are accessing a U.S. Government (USG) Information System (IS) that\\n\\ris provided for USG-authorized use only.\\n\\r\\n\\rBy using this IS (which includes any device attached to this IS), you\\n\\rconsent to the following conditions: \\n\\r\\n\\r-The USG routinely intercepts and monitors communications on this IS\\n\\rfor purposes including, but not limited to, penetration testing, COMSEC\\n\\rmonitoring, network operations and defense, personnel misconduct (PM),\\n\\rlaw enforcement (LE), and counterintelligence (CI) investigations. \\n\\r\\n\\r-At any time, the USG may inspect and seize data stored on this IS. \\n\\r\\n\\r-Communications using, or data stored on, this IS are not private, are\\n\\rsubject to routine monitoring, interception, and search, and may be\\n\\rdisclosed or used for any USG-authorized purpose. \\n\\r\\n\\r-This IS includes security measures (e.g., authentication and access\\n\\rcontrols) to protect USG interests--not for your personal benefit or\\n\\rprivacy. \\n\\r\\n\\r-Notwithstanding the above, using this IS does not constitute consent\\n\\rto PM, LE or CI investigative searching or monitoring of the content\\n\\rof privileged communications, or work product, related to personal\\n\\rrepresentation or services by attorneys, psychotherapists, or clergy,\\n\\rand their assistants. Such communications and work product are private\\n\\rand confidential. See User Agreement for details.\\n\\r\\n\\rlogin:"

If the herald string is not set, or it does not contain the Standard Mandatory DoD Notice and Consent Banner listed above, this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set the DoD banner to herald for the default stanza in /etc/security/login.cfg:

# chsec -f /etc/security/login.cfg -s default -a herald="You are accessing a U.S. Government (USG) Information System (IS) that\\n\\ris provided for USG-authorized use only.\\n\\r\\n\\rBy using this IS (which includes any device attached to this IS), you\\n\\rconsent to the following conditions: \\n\\r\\n\\r-The USG routinely intercepts and monitors communications on this IS\\n\\rfor purposes including, but not limited to, penetration testing, COMSEC\\n\\rmonitoring, network operations and defense, personnel misconduct (PM),\\n\\rlaw enforcement (LE), and counterintelligence (CI) investigations. \\n\\r\\n\\r-At any time, the USG may inspect and seize data stored on this IS. \\n\\r\\n\\r-Communications using, or data stored on, this IS are not private, are\\n\\rsubject to routine monitoring, interception, and search, and may be\\n\\rdisclosed or used for any USG-authorized purpose. \\n\\r\\n\\r-This IS includes security measures (e.g., authentication and access\\n\\rcontrols) to protect USG interests--not for your personal benefit or\\n\\rprivacy. \\n\\r\\n\\r-Notwithstanding the above, using this IS does not constitute consent\\n\\rto PM, LE or CI investigative searching or monitoring of the content\\n\\rof privileged communications, or work product, related to personal\\n\\rrepresentation or services by attorneys, psychotherapists, or clergy,\\n\\rand their assistants. Such communications and work product are private\\n\\rand confidential. See User Agreement for details.\\n\\r\\n\\rlogin:"'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16401r294060_chk'
  tag severity: 'medium'
  tag gid: 'V-215203'
  tag rid: 'SV-215203r508663_rule'
  tag stig_id: 'AIX7-00-001044'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-16399r294061_fix'
  tag 'documentable'
  tag legacy: ['SV-101557', 'V-91459']
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
