control 'SV-96873' do
  title 'The MaaS360 MDM server must be configured to display the required DoD warning banner upon administrator logon.

Note: This requirement is not applicable if the TOE platform is selected in FTA_TAB.1.1 in the Security Target (ST).'
  desc 'Note: The advisory notice and consent warning message is not required if the general purpose OS or network device displays an advisory notice and consent warning message when the administrator logs on to the general purpose OS or network device prior to accessing the MaaS360 MDM server or MaaS360 MDM server platform.

Before granting access to the system, the MaaS360 MDM server/server platform is required to display the DoD-approved system use notification message or banner that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met.

The approved DoD text must be used as specified in the KS referenced in DoDI 8500.01.

The non-bracketed text below must be used without any changes as the warning banner.

[A. Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating “OK.”]

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

SFR ID: FMT_SMF.1.1(2) d'
  desc 'check', 'Review the MaaS360 server console configuration to determine if before establishing a user session, the server displays an administrator-specified advisory notice and consent warning message regarding use of the MaaS360 server.

On the MaaS360 console complete the following steps:
1. Have a System Administrator log on to the portal.
2. Verify that the approved DoD Banner is displayed before the user obtains access to the console.

If the MaaS360 server does not display an administrator-specified advisory notice and consent warning message regarding use of the MaaS360 server before establishing a user session, this is a finding.'
  desc 'fix', 'Configure the MaaS360 server to display the appropriate warning banner text.

For SaaS, this step can only be implemented by the IBM Master Administrator. Ensure that "Branding UI" and "Admin Portal Usage Agreement" are enabled. The IBM Master Administrator will then edit the Terms of Agreement with the text provided by the DoD.'
  impact 0.3
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81959r1_chk'
  tag severity: 'low'
  tag gid: 'V-82159'
  tag rid: 'SV-96873r1_rule'
  tag stig_id: 'M360-10-006700'
  tag gtitle: 'PP-MDM-311056'
  tag fix_id: 'F-89013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
