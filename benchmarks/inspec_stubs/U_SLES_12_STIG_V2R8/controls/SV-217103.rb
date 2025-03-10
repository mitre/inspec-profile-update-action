control 'SV-217103' do
  title 'The SUSE operating system must display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access to the local graphical user interface.'
  desc 'Display of a standardized and approved use notification before granting access to the SUSE operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

The banner must be acknowledged by the user prior to allowing the user access to the SUSE operating system. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for the SUSE operating system:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

'
  desc 'check', 'Verify the SUSE operating system displays the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on via the local graphical user interface. 

Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Check the configuration by running the following command:

# more /etc/gdm/Xsession

The beginning of the file must contain the following text immediately after (#!/bin/sh):

if ! zenity --text-info \\
--title "Consent" \\
--filename=/etc/gdm/banner \\
--no-markup \\
--checkbox="Accept." 10 10; then
sleep 1;
exit 1;
fi

If the beginning of the file does not contain the above text immediately after the line (#!/bin/sh), this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access.

Add the following content to the file "/etc/gdm/Xsession" below the line #!/bin/sh:

if ! zenity --text-info \\
--title "Consent" \\
--filename=/etc/gdm/banner \\
--no-markup \\
--checkbox="Accept." 10 10; then
sleep 1;
exit 1;
fi

Save the file "/etc/gdm/Xsession".'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18331r369465_chk'
  tag severity: 'medium'
  tag gid: 'V-217103'
  tag rid: 'SV-217103r603262_rule'
  tag stig_id: 'SLES-12-010020'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-18329r369466_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007']
  tag 'documentable'
  tag legacy: ['SV-91745', 'V-77049']
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
