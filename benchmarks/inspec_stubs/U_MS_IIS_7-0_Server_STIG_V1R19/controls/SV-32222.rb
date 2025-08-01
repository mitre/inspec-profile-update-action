control 'SV-32222' do
  title 'The use of Internet Printing Protocol (IPP) must be disabled on the IIS web server.'
  desc 'The use of Internet Printing Protocol (IPP) on an  IIS web server allows client’s access to shared printers.  This privileged access could allow remote code execution by increasing the web servers attack surface.  Additionally, since IPP does not support SSL, it is considered a risk and will not be deployed.'
  desc 'check', 'If the Print Services role and the Internet Printing role are not installed, this check is N/A.

Navigate to the following directory:
%windir%\\web\\printers
If this folder exists, this is a finding.

Determine whether Internet Printing is enabled: 
1.  Click Start, then click Administrative Tools, and then click Server Manager.
2.  Expand the roles node, then right-click Print Services, and then select Remove Roles Services.
3.  If the Internet Printing option is enabled, this is a finding.'
  desc 'fix', '1. Click Start, then click Administrative Tools, and then click Server Manager.
2. Expand the roles node, then right-click Print Services, and then select Remove Roles Services.
3. If the Internet Printing option is checked, clear the check box, click Next, and then click Remove to complete the wizard.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6754'
  tag rid: 'SV-32222r2_rule'
  tag stig_id: 'WA000-WI080 IIS7'
  tag gtitle: 'WA000-WI080'
  tag fix_id: 'F-28783r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
