control 'SV-80121' do
  title 'Before establishing a user session, the MaaS360 Server must display an administrator-specified advisory notice and consent warning message regarding use of the MaaS360 Server.'
  desc 'Note:  The advisory notice and consent warning message is not required if the General Purpose OS or Network Device displays an advisory notice and consent warning message when the administrator logs on to  the General Purpose OS or Network Device prior to accessing the MaaS360 Server or MaaS360 Server platform.

The MaaS360 Server/server platform is required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. This ensures the legal requirements for auditing and monitoring are met. 

The approved DoD text must be used as specified in KS referenced in DoDI 8500.01.

The non-bracketed text below must be used without any changes as the warning banner.  
 
[A. Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating “OK.”]
 
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

SFR ID: FMT_SMF_EXT.1.1(2) Refinement'
  desc 'check', 'Review the MaaS360 server console configuration to determine if before establishing a user session, the server displays an administrator-specified advisory notice and consent warning message regarding use of the MaaS360 Server.  

On the MaaS360 console complete the following steps:
Have a System Administrator log-in to the portal and verify that the approved DoD Banner is displayed before the user obtains access to the console.

If the MaaS360 server does not display an administrator-specified advisory notice and consent warning message regarding use of the MaaS360 Server before establishing a user session, this is a finding.'
  desc 'fix', 'Configure the MaaS360 Server to display the appropriate warning banner text.

For SaaS this step can only be implemented by IBM Master Administrator. Ensure that "Branding UI", and "Admin Portal Usage Agreement" are enabled. Then  the IBM Master Administrator will edit the Terms of Agreement with the text provided by the Department of the Defense. 

For On-Premise this step can be implemented by the Master Administrator account created by the user. Ensure that "Branding UI", and "Admin Portal Usage Agreement" are enabled. Then  the IBM Master Administrator will edit the Terms of Agreement with the text provided by the Department of the Defense.'
  impact 0.3
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-66191r1_chk'
  tag severity: 'low'
  tag gid: 'V-65631'
  tag rid: 'SV-80121r1_rule'
  tag stig_id: 'M360-01-000100'
  tag gtitle: 'PP-MDM-201100'
  tag fix_id: 'F-71559r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
