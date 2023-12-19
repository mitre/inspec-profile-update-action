control 'SV-215201' do
  title 'The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts on AIX.'
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
  desc 'check', 'If AIX CDE (X11) is not used, this is Not Applicable.

Check if file "/etc/dt/config/en_US/Xresources" exists:
# ls /etc/dt/config/en_US/Xresources 

If the file does not exist, this is a finding.

Check if the "Dtlogin*greeting.labelString" is set to the Standard Mandatory DoD Notice and Consent Banner:
# grep "Dtlogin*greeting.labelString" /etc/dt/config/en_US/Xresources

The above command should display the following:
Dtlogin*greeting.labelString: You are accessing a U.S. Government (USG) Information System (IS) that\\nis provided for USG-authorized use only.\\n\\nBy using this IS (which includes any device attached to this IS), you\\nconsent to the following conditions: \\n\\n-The USG routinely intercepts and monitors communications on this IS\\nfor purposes including, but not limited to, penetration testing, COMSEC\\nmonitoring, network operations and defense, personnel misconduct (PM),\\nlaw enforcement (LE), and counterintelligence (CI) investigations. \\n\\n-At any time, the USG may inspect and seize data stored on this IS. \\n\\n-Communications using, or data stored on, this IS are not private, are\\nsubject to routine monitoring, interception, and search, and may be\\ndisclosed or used for any USG-authorized purpose. \\n\\n-This IS includes security measures (e.g., authentication and access\\ncontrols) to protect USG interests--not for your personal benefit or\\nprivacy. \\n\\n-Notwithstanding the above, using this IS does not constitute consent\\nto PM, LE or CI investigative searching or monitoring of the content\\nof privileged communications, or work product, related to personal\\nrepresentation or services by attorneys, psychotherapists, or clergy,\\nand their assistants. Such communications and work product are private\\nand confidential. See User Agreement for details. 

If the "Dtlogin*greeting.labelString" variable is not set, or the label string does not contain the Standard Mandatory DoD Notice and Consent Banner, this is a finding.'
  desc 'fix', 'Edit the "Xresources" file to configure the system to display one of the DoD login banners (based on the character limitations imposed by the system) prior to, or as part of, the graphical desktop environment login process. 

For "Dtlogin", change the variable "Dtlogin*greeting.labelString:" in "Xresources" file. 

# cp /usr/dt/config/C/Xresources /etc/dt/config/en_US/Xresources 

# vi /etc/dt/config/en_US/Xresources

Set variable "Dtlogin*greeting.labelString" as the following:
Dtlogin*greeting.labelString: You are accessing a U.S. Government (USG) Information System (IS) that\\nis provided for USG-authorized use only.\\n\\nBy using this IS (which includes any device attached to this IS), you\\nconsent to the following conditions: \\n\\n-The USG routinely intercepts and monitors communications on this IS\\nfor purposes including, but not limited to, penetration testing, COMSEC\\nmonitoring, network operations and defense, personnel misconduct (PM),\\nlaw enforcement (LE), and counterintelligence (CI) investigations. \\n\\n-At any time, the USG may inspect and seize data stored on this IS. \\n\\n-Communications using, or data stored on, this IS are not private, are\\nsubject to routine monitoring, interception, and search, and may be\\ndisclosed or used for any USG-authorized purpose. \\n\\n-This IS includes security measures (e.g., authentication and access\\ncontrols) to protect USG interests--not for your personal benefit or\\nprivacy. \\n\\n-Notwithstanding the above, using this IS does not constitute consent\\nto PM, LE or CI investigative searching or monitoring of the content\\nof privileged communications, or work product, related to personal\\nrepresentation or services by attorneys, psychotherapists, or clergy,\\nand their assistants. Such communications and work product are private\\nand confidential. See User Agreement for details. 

Save the above change to "Xresources" file.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16399r294054_chk'
  tag severity: 'medium'
  tag gid: 'V-215201'
  tag rid: 'SV-215201r508663_rule'
  tag stig_id: 'AIX7-00-001042'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-16397r294055_fix'
  tag 'documentable'
  tag legacy: ['V-91223', 'SV-101323']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
