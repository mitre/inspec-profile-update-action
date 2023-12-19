control 'SV-221655' do
  title 'The Oracle Linux operating system must display the approved Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy.

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

'
  desc 'check', %q(Verify the operating system displays the approved Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a graphical user logon.

Note: If the system does not have a Graphical User Interface installed, this requirement is Not Applicable. 

Check that the operating system displays the exact approved Standard Mandatory DoD Notice and Consent Banner text with the command:

# grep banner-message-text /etc/dconf/db/local.d/*
banner-message-text=
'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'

Note: The "\n" characters are for formatting only. They will not be displayed on the Graphical User Interface.

If the banner does not match the approved Standard Mandatory DoD Notice and Consent Banner, this is a finding.)
  desc 'fix', %q(Configure the operating system to display the approved Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

Note: If the system does not have a Graphical User Interface installed, this requirement is Not Applicable.

Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:

# touch /etc/dconf/db/local.d/01-banner-message

Add the following line to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

[org/gnome/login-screen]

banner-message-enable=true

banner-message-text='You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'

Note: The "\n" characters are for formatting only. They will not be displayed on the Graphical User Interface.

Run the following command to update the database:
# dconf update)
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36266r602392_chk'
  tag severity: 'medium'
  tag gid: 'V-221655'
  tag rid: 'SV-221655r603260_rule'
  tag stig_id: 'OL07-00-010040'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-36230r602393_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag legacy: ['V-99051', 'SV-108155']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
