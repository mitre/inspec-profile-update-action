control 'SV-240348' do
  title 'The SLES for vRealize must display the Standard Mandatory DoD Notice and Consent Banner before granting access via SSH.'
  desc %q(Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

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
  desc 'check', %q(Check that the SSH daemon is configured for logon warning banners:

# grep -i banner /etc/ssh/sshd_config | grep -v '#'

If the output does not contain "Banner /etc/issue", this is a finding.)
  desc 'fix', 'To configure the SSH daemon for the logon warning banners, modify /etc/ssh/sshd_config with the following command:

# sed -i "/^[^#]*Banner/ c\\Banner /etc/issue" /etc/ssh/sshd_config

The SSH service will need to be restarted after the above change has been made to SSH. This can be done by running the following command:

# service sshd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43581r670783_chk'
  tag severity: 'medium'
  tag gid: 'V-240348'
  tag rid: 'SV-240348r670785_rule'
  tag stig_id: 'VRAU-SL-000030'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-43540r670784_fix'
  tag 'documentable'
  tag legacy: ['SV-100123', 'V-89473']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
