control 'SV-108681' do
  title 'The Jamf Pro EMM server must be configured to display the required DoD warning banner upon administrator logon.

Note: This requirement is not applicable if the TOE platform is selected in FTA_TAB.1.1 in the Security Target (ST).'
  desc 'Note: The advisory notice and consent warning message is not required if the general purpose OS or network device displays an advisory notice and consent warning message when the administrator logs on to the general purpose OS or network device prior to accessing the Jamf Pro EMM server or Jamf Pro EMM server platform.

Before granting access to the system, the Jamf Pro EMM server/server platform is required to display the DoD-approved system use notification message or banner that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met.

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
  desc 'check', 'Verify the Jamf Pro EMM server for customized login page:

Go to /path/to/JSS/Tomcat/webapps/ROOT/WEB-INF/frontend folder.

Find the login.jsp.

Locate new <body> content related to customized text for DoD classification.

Verify the DoD warning banner text is correct.

If the Jamf Pro EMM server is not configured to display DoD warning banner when the system administrator logs on to the server, this is a finding.'
  desc 'fix', 'Configure the Jamf Pro EMM server for customized login page:

Go to  /path/to/JSS/Tomcat/webapps/ROOT/WEB-INF/frontend>>Open the login.jsp with a text editor application.

Scroll to the bottom of the page by the line "<input type="submit" class="button" value="log in" />"
Under the </div> create a new line and paste the following:

NOTE: Anything under "style" and "body" can be customized to fit your environments needs.<head>
        <style>
                p {margin-top:1em}
                p {margin-bottom:0em}
                p {color:red}
                p {text-align:center}
                p {font-family:courier}
                p {font-size:100%}
        </style>
</head>
<body>
        <p>""Place DoD warning banner first line here""</p>
        <p>""place second (or next) line here""</p>
</body>

Restart Tomcat for changes to take effect.'
  impact 0.3
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98427r1_chk'
  tag severity: 'low'
  tag gid: 'V-99577'
  tag rid: 'SV-108681r1_rule'
  tag stig_id: 'JAMF-10-000550'
  tag gtitle: 'PP-MDM-411056'
  tag fix_id: 'F-105261r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
