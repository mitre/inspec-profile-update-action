control 'SV-215202' do
  title 'The Department of Defense (DoD) login banner must be displayed during SSH, sftp, and scp login sessions on AIX.'
  desc %q(Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

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
  desc 'check', 'Check if file "/etc/motd.ssh" exists:
# ls /etc/motd.ssh

If the file does not exist, this is a finding.

Check if "/etc/motd.ssh" contains The Standard Mandatory DoD Notice and Consent Banner:
# cat /etc/motd.ssh

The above command should display the following Standard Mandatory DoD Notice and Consent Banner:
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 

By using this IS (which includes any device attached to this IS), you consent to the following conditions: 

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 

-At any time, the USG may inspect and seize data stored on this IS. 

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 

If the Standard Mandatory DoD Notice and Consent Banner is not displayed by the "cat" command, this is a finding.

Check if  /etc/motd.ssh is used as banner file in SSH config file:
# grep -i "Banner /etc/motd.ssh" /etc/motd.ssh

If the above grep command does not find "Banner /etc/motd.ssh" in the "/etc/motd.ssh" file, this is a finding.'
  desc 'fix', 'Create file "/etc/motd.ssh" to contain the following:
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Modify "/etc/ssh/sshd_config" to contain the following line:
Banner /etc/motd.ssh

Restart the SSH daemon by running the following commands:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16400r294057_chk'
  tag severity: 'medium'
  tag gid: 'V-215202'
  tag rid: 'SV-215202r508663_rule'
  tag stig_id: 'AIX7-00-001043'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-16398r294058_fix'
  tag 'documentable'
  tag legacy: ['SV-101325', 'V-91225']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
