control 'SV-217105' do
  title 'The SUSE operating system must display a banner before granting local or remote access to the system via a graphical user logon.'
  desc 'Display of a standardized and approved use notification before granting access to the SUSE operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

The banner must be acknowledged by the user prior to allowing the user access to the SUSE operating system. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for SUSE operating system:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  desc 'check', 'Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Verify the SUSE operating system to display a banner before local or remote access to the system via a graphical user logon.

Check that the SUSE operating system displays a banner at the logon screen by performing the following command:

> grep banner-message-enable /etc/dconf/db/gdm.d/*
banner-message-enable=true

> cat /etc/dconf/profile/gdm
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults

If "banner-message-enable" is set to "false" or is missing completely, this is a finding.'
  desc 'fix', 'Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Configure the SUSE operating system to display a banner before local or remote access to the system via a graphical user logon.

Create a database that will contain the system wide graphical user logon settings (if it does not already exist) with the following command:

> sudo touch /etc/dconf/db/gdm.d/01-banner-message

Add the following line to the "[org/gnome/login-screen]" section of the "/etc/dconf/db/gdm.d/01-banner-message" file:

[org/gnome/login-screen]
banner-message-enable=true

Update the system databases:

> sudo dconf update

Users must log out and back in again before the system-wide settings take effect.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-36356r646676_chk'
  tag severity: 'medium'
  tag gid: 'V-217105'
  tag rid: 'SV-217105r646678_rule'
  tag stig_id: 'SLES-12-010040'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-36319r646677_fix'
  tag 'documentable'
  tag legacy: ['V-77053', 'SV-91749']
  tag cci: ['CCI-001387', 'CCI-001388', 'CCI-001384', 'CCI-001385', 'CCI-001386']
  tag nist: ['AC-8 c 2', 'AC-8 c 3', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2']
end
