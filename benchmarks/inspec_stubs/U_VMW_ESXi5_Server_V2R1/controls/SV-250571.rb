control 'SV-250571' do
  title 'The GID assigned to a user must exist.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with that GID is subsequently created, the user may have unintended rights to that group.'
  desc 'check', %q(From the vSphere Client/vCenter, click on the "Local Users and Groups" tab, then select to view Groups.  Select to view Users. Highlight the user, right click and select Edit. Click Cancel.

If any user's primary GID is not found in the Group list, this is a finding.)
  desc 'fix', %q(From the vSphere Client/vCenter, click on the "Local Users and Groups" tab, then select Groups. Highlight the user, right click the user and select Edit. Select/highlight/assign the user's correct primary GID. Click OK.)
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54006r798710_chk'
  tag severity: 'low'
  tag gid: 'V-250571'
  tag rid: 'SV-250571r798712_rule'
  tag stig_id: 'GEN000380-ESXI5-000043'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53960r798711_fix'
  tag 'documentable'
  tag legacy: ['V-39274', 'SV-51090']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
