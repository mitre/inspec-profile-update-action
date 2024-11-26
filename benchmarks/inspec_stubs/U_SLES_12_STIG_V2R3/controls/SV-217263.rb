control 'SV-217263' do
  title 'The SUSE operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting access via SSH.'
  desc 'Display of a standardized and approved use notification before granting access to the SUSE operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for SUSE operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

'
  desc 'check', 'Verify the SUSE operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.

Check the issue file to verify that it contains one of the DoD required banners. If it does not, this is a finding.

# more /etc/issue

The output must display the following DoD-required banner text. 

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the output does not display the banner text, this is a finding.

Check the banner setting for sshd_config:

# sudo grep "Banner" /etc/ssh/sshd_config

The output must show the value of "Banner" set to "/etc/issue". An example is shown below:

# sudo grep "Banner" /etc/ssh/sshd_config
Banner /etc/issue

If it does not, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system by running the following commands:

Edit the "sshd_config" file and edit the Banner flag to be the following:

Banner /etc/issue/

Restart the sshd daemon:

# sudo systemctl restart sshd.service

To configure the system logon banner, edit the "/etc/issue" file. Replace the default text inside with the Standard Mandatory DoD banner text:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18491r369945_chk'
  tag severity: 'medium'
  tag gid: 'V-217263'
  tag rid: 'SV-217263r603262_rule'
  tag stig_id: 'SLES-12-030050'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-18489r369946_fix'
  tag satisfies: ['SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag legacy: ['SV-92135', 'V-77439']
  tag cci: ['CCI-001386', 'CCI-001387', 'CCI-001388', 'CCI-001384', 'CCI-001385', 'CCI-000048']
  tag nist: ['AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 a']
end
