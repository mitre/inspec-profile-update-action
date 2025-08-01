control 'SV-216160' do
  title 'The GNOME service must display the DoD approved system use notification message or banner before granting access to the system.'
  desc 'Warning messages inform users who are attempting to log in to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. As implementing a logon banner to deter inappropriate use can provide a foundation for legal action against abuse, this warning content should be set as appropriate.'
  desc 'check', 'This item does not apply if a graphic login is not configured.

Log in to the Gnome Graphical interface. If the approved banner message does not appear, this is a finding.

# cat /etc/issue

# grep /etc/gdm/Init/Default zenity

If /etc/issue does not contain that DoD-approved banner message or /etc/gdm/Init/Default does not contain the line:

/usr/bin/zenity --text-info --width=800 --height=300 \\
--title="Security Message" --filename=/etc/issue

this is a finding.'
  desc 'fix', 'The root role is required.

If the system does not use XWindows, this is not applicable.

# pfedit /etc/issue 

Insert the proper DoD banner message text. The DoD required text is:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

# pfedit /etc/gdm/Init/Default

Add the following content before the "exit 0" line of the file.

/usr/bin/zenity --text-info --width=800 --height=300 \\
--title="Security Message" --filename=/etc/issue'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17398r372862_chk'
  tag severity: 'low'
  tag gid: 'V-216160'
  tag rid: 'SV-216160r603268_rule'
  tag stig_id: 'SOL-11.1-050410'
  tag gtitle: 'SRG-OS-000023'
  tag fix_id: 'F-17396r372863_fix'
  tag 'documentable'
  tag legacy: ['V-48203', 'SV-61075']
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
