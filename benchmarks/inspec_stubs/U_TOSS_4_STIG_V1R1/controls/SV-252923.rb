control 'SV-252923' do
  title 'TOSS must display the Standard Mandatory DoD Notice and Consent Banner or equivalent US Government Agency Notice and Consent Banner before granting local or remote access to the system via a ssh logon.'
  desc 'Display of a standardized and approved use notification before granting access to TOSS ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD or other US Government Agency policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'check', 'Verify that TOSS displays the Standard Mandatory DoD Notice and Consent Banner or equivalent US Government Agency Notice and Consent Banner before granting access to the system when connecting from outside of the cluster.

Check for the location of the banner file being used with the following command:

$ sudo grep -i banner /etc/ssh/sshd_config
banner /etc/issue

This command will return the banner keyword and the name of the file that contains the ssh banner (in this case "/etc/issue").

If the line is commented out, this is a finding.

For nodes of the cluster that are only privately (within the cluster) accessible, this requirement is Not Applicable.

View the file specified by the banner keyword to check that it matches the text of the Standard Mandatory DoD Notice and Consent Banner:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the system has a graphical logon capability and does not display a graphical logon banner, this is a finding.

If the text in the file does not match the Standard Mandatory DoD Notice and Consent Banner or equivalent US Government Agency Notice and Consent Banner, this is a finding.'
  desc 'fix', 'Configure TOSS to display the Standard Mandatory DoD Notice and Consent Banner or equivalent US Government Agency Notice and Consent Banner before granting access to the system.

Edit the "/etc/ssh/sshd_config" file to uncomment the banner keyword and configure it to point to a file that will contain the logon banner (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). An example configuration line is:

banner /etc/issue

The banner must be formatted in accordance with applicable DoD or other US Government Agency policy.

Edit the "/etc/issue" file to replace the default text with the Standard Mandatory DoD Notice and Consent Banner or equivalent US Government Agency Notice and Consent Banner. The DoD-required text is:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
  impact 0.3
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56376r824091_chk'
  tag severity: 'low'
  tag gid: 'V-252923'
  tag rid: 'SV-252923r824093_rule'
  tag stig_id: 'TOSS-04-010120'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-56326r824092_fix'
  tag 'documentable'
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
