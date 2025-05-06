control 'SV-209035' do
  title 'The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.'
  desc 'An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.'
  desc 'check', %q(If the GConf2 package is not installed, this is not applicable.

To ensure login warning banner text is properly set, run the following:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text

If properly configured, the proper banner text will appear within this schema.

The DoD required text is either:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR:

"I've read & consent to terms in IS user agreem't."

If the DoD required banner text does not appear in the schema, this is a finding.)
  desc 'fix', %q(To set the text shown by the GNOME Display Manager in the login screen, run the following command:

# gconftool-2
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gdm/simple-greeter/banner_message_text \
"[DoD required text]"

Where the DoD required text is either:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR:

"I've read & consent to terms in IS user agreem't."

When entering a warning banner that spans several lines, remember to begin and end the string with """. This command writes directly to the file "/etc/gconf/gconf.xml.mandatory/apps/gdm/simple-greeter/%gconf.xml", and this file can later be edited directly if necessary.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9288r357890_chk'
  tag severity: 'medium'
  tag gid: 'V-209035'
  tag rid: 'SV-209035r603263_rule'
  tag stig_id: 'OL6-00-000326'
  tag gtitle: 'SRG-OS-000228'
  tag fix_id: 'F-9288r357891_fix'
  tag 'documentable'
  tag legacy: ['V-51125', 'SV-65335']
  tag cci: ['CCI-001388', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387']
  tag nist: ['AC-8 c 3', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2']
end
