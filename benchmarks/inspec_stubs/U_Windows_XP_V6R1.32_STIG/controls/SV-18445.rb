control 'SV-18445' do
  title 'ACLs for system files and directories do not conform to minimum requirements.'
  desc 'Failure to properly configure ACL file and directory permissions, allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.'
  desc 'check', 'The default ACL settings are adequate when the Security Option “Network access: Let everyone permissions apply to anonymous users” is set to “Disabled” (V-3377) and Power User Group Membership is restricted.  If the default ACLs are maintained, the referenced option is set to “Disabled” and Powers Users are restricted, this check should normally be marked “Not a Finding”

Specific System files are an exception to this. The following will be configured with only Administrators and System having Full Permissions: 

\\regedit.exe 
\\System32\\arp.exe 
\\System32\\at.exe 
\\System32\\attrib.exe 
\\System32\\cacls.exe 
\\System32\\debug.exe 
\\System32\\edlin.exe 
\\System32\\eventcreate.exe 
\\System32\\eventtriggers.exe 
\\System32\\ftp.exe 
\\System32\\nbtstat.exe 
\\System32\\net.exe 
\\System32\\net1.exe 
\\System32\\netsh.exe 
\\System32\\netstat.exe 
\\System32\\nslookup.exe 
\\System32\\ntbackup.exe 
\\System32\\rcp.exe 
\\System32\\reg.exe 
\\System32\\regedt32.exe 
\\System32\\regini.exe 
\\System32\\regsvr32.exe 
\\System32\\rexec.exe 
\\System32\\route.exe 
\\System32\\rsh.exe 
\\System32\\sc.exe 
\\System32\\secedit.exe 
\\System32\\subst.exe 
\\System32\\Systeminfo.exe 
\\System32\\telnet.exe 
\\System32\\tftp.exe 
\\System32\\tlntsvr.exe 

\\System32\\mshta.exe will have Users – Read and Execute in addition to the permissions above.

Documentable Explanation: If an ACL setting prevents a site’s applications from performing properly, the site can modify that specific setting. Settings should only be changed to the minimum necessary for the application to function. Each exception to the recommended settings should be documented and kept on file by the IAO.'
  desc 'fix', 'Maintain the default file ACLs, configure the Security Option: “Network access: Let everyone permissions apply to anonymous users” to “Disabled” (V-3377) and restrict the Power Users group to include no members.

Configure permissions on the following so that only Administrators and System have Full (no other permissions assigned to other accounts or groups).

\\regedit.exe 
\\System32\\arp.exe 
\\System32\\at.exe 
\\System32\\attrib.exe 
\\System32\\cacls.exe 
\\System32\\debug.exe 
\\System32\\edlin.exe 
\\System32\\eventcreate.exe 
\\System32\\eventtriggers.exe 
\\System32\\ftp.exe 
\\System32\\nbtstat.exe 
\\System32\\net.exe 
\\System32\\net1.exe 
\\System32\\netsh.exe 
\\System32\\netstat.exe 
\\System32\\nslookup.exe 
\\System32\\ntbackup.exe 
\\System32\\rcp.exe 
\\System32\\reg.exe 
\\System32\\regedt32.exe 
\\System32\\regini.exe 
\\System32\\regsvr32.exe 
\\System32\\rexec.exe 
\\System32\\route.exe 
\\System32\\rsh.exe 
\\System32\\sc.exe 
\\System32\\secedit.exe 
\\System32\\subst.exe 
\\System32\\Systeminfo.exe 
\\System32\\telnet.exe 
\\System32\\tftp.exe 
\\System32\\tlntsvr.exe

\\System32\\mshta.exe will have Users – Read and Execute in addition to the permissions above.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32954r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1130'
  tag rid: 'SV-18445r1_rule'
  tag gtitle: 'System File ACLs'
  tag fix_id: 'F-29105r1_fix'
  tag false_positives: 'If a manual check of a questionable ACL setting shows that it has been set to meet or is more restrictive than minimum requirements, then it will not be counted as a finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
