control 'SV-44065' do
  title 'HTTP authenticated access must be set to Integrated Windows Authentication only.'
  desc 'This feature controls the authentication method used to connect to the OWA virtual directories. 
Ensure this is set to Integrated Windows Authentication only.

Anonymous access provides for no access control. Basic Authentication transmits the password in the clear and risks exposure, and the other methods are not recommended by Microsoft for this control. 

Failure to configure this as per the recommendation may result in unrestricted access to OWA virtual directory, passwords being sent in the clear, and/or the inability to correctly authenticate, depending on which change is made.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-OwaVirtualDirectory -server ‘<Identity Name>’ | Select Name,Identity,*Authentication
 
If the ‘WindowsAuthentication’ is not ‘True’, this is a finding. If any other result for ‘WindowsAuthentication’ is set to 'True', this is a finding.

NOTE: Typical results for this command would result in this display:
Name : owa (Default Web Site)
Identity : <Identity Name>\\owa (Default Web Site)
BasicAuthentication : False
WindowsAuthentication : True
DigestAuthentication : False
FormsAuthentication : False
LiveIdAuthentication : False"
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-OwaVirtualDirectory -WindowsAuthentication $true -Identity '<IdentityName>'"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41755r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33645'
  tag rid: 'SV-44065r2_rule'
  tag stig_id: 'Exch-1-208'
  tag gtitle: 'Exch-1-208'
  tag fix_id: 'F-37538r1_fix'
  tag 'documentable'
end
