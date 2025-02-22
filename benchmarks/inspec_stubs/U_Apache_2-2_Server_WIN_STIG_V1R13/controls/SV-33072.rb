control 'SV-33072' do
  title 'Web administration tools must be restricted to the web manager and the web manager’s designees.'
  desc 'All automated information systems are at risk of data loss due to disaster or compromise. Failure to provide adequate protection to the administration tools creates risk of potential theft or damage that may ultimately compromise the mission.  Adequate protection ensures that server administration operates with less risk of losses or operations outages.  The key web service administrative and configuration tools must be accessible only by the authorized web server administrators. All users granted this authority must be documented and approved by the ISSO. Access to the IIS Manager will be limited to authorized users and administrators.'
  desc 'check', 'Configuration of the Apache web server is accomplished by editing flat .conf files. 
Interview the ISSO and ask for the web server’s documented procedures and processes.

Verify the documented procedures and processes explicitly document the roles and responsibilities for the web server and web site(s) management. These documented roles will be used to validate access controls for this check.
For the purpose of this check, the SA is responsible for the OS platform of the webserver. The web server manager manages the Apache installation and configuration and the web master manages the web site or sites. 
In some environments, the SA is also the web manager/web master. In such case, the roles should still be documented.
Locate the folder in which the Apache installation’s httpd.conf and supporting .conf files are located. Right-click on the folder name and select “Properties”. Select the “Security” tab and review the accounts and assigned permissions. 
The System Administrator(s), web manager(s) and web master(s), as identified in the organization’s documentation, may have Full Control to the installation folder and sub-folders.
Non-documented administrators, non-elevated administrators and users may have Read only permissions to the installation folder and sub-folders.

If any accounts other than the documented SA, web manager, or web manager designees have greater than Read permissions to the web administration tool or control files, this is a finding.'
  desc 'fix', 'Restrict access to the httpd.conf and supporting .conf files to only the documented SA, web manager, or web manager designees.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33743r3_chk'
  tag severity: 'medium'
  tag gid: 'V-2248'
  tag rid: 'SV-33072r4_rule'
  tag stig_id: 'WG220 W22'
  tag gtitle: 'WG220'
  tag fix_id: 'F-29378r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
