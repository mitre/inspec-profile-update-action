control 'SV-254132' do
  title 'Nutanix AOS must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access.'
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

"I've read & consent to terms in IS user agreem't."

)
  desc 'check', 'Verify that the Standard Mandatory DoD Notice and Consent Banner is configured.

Verify that SSH is configured to display the Standard Mandatory DoD Notice Consent Banner:
$ sudo grep -i banner /etc/ssh/sshd_config
banner /etc/issue

If "banner" is not set or is commented out, this is a finding.'
  desc 'fix', "Configure the Standard Mandatory DoD Notice and Consent Banner.

$ ncli cluster edit-cvm-security-params enable-banner=true'"
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57617r846482_chk'
  tag severity: 'low'
  tag gid: 'V-254132'
  tag rid: 'SV-254132r846484_rule'
  tag stig_id: 'NUTX-OS-000240'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-57568r846483_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
