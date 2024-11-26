control 'SV-233885' do
  title 'The Infoblox system must display the approved DoD notice and consent banner.'
  desc 'Configuration of the DoD notice and consent banner requires all administrators to acknowledge the current DoD notice and consent by clicking an "Accept" button.'
  desc 'check', %q(Navigation to the HTTPS interface on the Grid Master using a web browser will display the current DoD banner. 

1. If an administrator is currently logged in, click on the drop-down menu adjacent to the administrator's name in the upper right side and select "Logout". 
2. Open a new session to the Infoblox system and review the banner presented. 
3. The banner text of the document MUST read:  

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:   -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.  -At any time, the USG may inspect and seize data stored on this IS.   -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.  -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.  -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential. See User Agreement for details."  

If the correct banner is not displayed, this is a finding.)
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties on a stand-alone system. 
2. Toggle Advanced mode. Select "Security", "Advanced" tab.  
3. Click "Enable Notice and Consent Banner".  
4. Use the text box to enter the appropriate banner.  
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  
6. Administrators should log out and close the web browser.  
7. It may be necessary to clear the web browser cache for the banner to display or update on a session opened shortly after reconfiguration.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37070r611175_chk'
  tag severity: 'medium'
  tag gid: 'V-233885'
  tag rid: 'SV-233885r621666_rule'
  tag stig_id: 'IDNS-8X-400027'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-37035r611176_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
