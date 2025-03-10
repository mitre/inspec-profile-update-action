control 'SV-46357' do
  title 'Access to web administration tools must be restricted to the web manager and the web managers designees.'
  desc 'The key web service administrative and configuration tools must only be accessible by the web server staff.  All users granted this authority will be documented and approved by the ISSO. Access to the IIS Manager will be limited to authorized users and administrators.'
  desc 'check', '1. Open the IIS Manager and select Properties.
2. Select the Shortcut tab, and then left-click Open File Location.
3. Right-click InetMgr.exe, then click Properties from the context menu.
4. Select the Security tab.
5. Review the groups and user names.

The following account may have Full control priviledges:
TrustedInstaller

The following accounts may have read & execute, and read permissions:
Administrators (non-elevated)
System
Users

Specific users may be granted read & execute and read permissions.  Compare the local documentation authorizing specific users, against the specific users observed in step 5.  If any other access is observed, this is a finding.'
  desc 'fix', 'Restrict access to the web administration tool to only the web manager and the web manager’s designees.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32734r5_chk'
  tag severity: 'medium'
  tag gid: 'V-2248'
  tag rid: 'SV-46357r3_rule'
  tag stig_id: 'WG220 IIS7'
  tag gtitle: 'WG220'
  tag fix_id: 'F-26807r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
