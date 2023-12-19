control 'SV-33095' do
  title 'Wscript.exe and Cscript.exe must only be accessible by the SA and/or the web administrator.'
  desc 'Windows Scripting Host (WSH) is installed under either a Typical or Custom installation option of a Microsoft Network Server. This technology permits the execution of powerful script files from the Windows NT command line. This technology is also classified as a Category I Mobile Code. If the access to these files is not tightly controlled, a malicious user could readily compromise the server by using a form to send input to these scripting engines.'
  desc 'check', 'Search for instances of Wscript.exe and Cscript.exe.

Move to these files, if found, and right-click on them to view their Properties.

Permissions should only exist for System, the SA, and the web administrator, who may have Full Control. User accounts with access to these files that are unknown, or unintended, should be removed.

If these files have permission for other than the SA, the web administrator, or the system, this is a finding.'
  desc 'fix', 'Remove Wscript.exe and Cscript.exe files from the server, or restrict access to these files to the SA, the web administrator, and the system account.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2264'
  tag rid: 'SV-33095r1_rule'
  tag stig_id: 'WG470 W22'
  tag gtitle: 'WG470'
  tag fix_id: 'F-29397r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
