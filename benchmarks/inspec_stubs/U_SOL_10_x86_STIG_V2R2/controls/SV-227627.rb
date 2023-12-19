control 'SV-227627' do
  title 'NIS/NIS+/yp command files must not have extended ACLs.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  ACLs on these files could result in unauthorized modification, which could compromise these processes and the system."
  desc 'check', 'Verify NIS/NIS+/yp files have no extended ACLs.
# ls -lLRa /usr/lib/netsvc/yp /var/yp
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the directory and files.
# chmod -R A- /usr/lib/netsvc/yp /var/yp'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29789r488441_chk'
  tag severity: 'medium'
  tag gid: 'V-227627'
  tag rid: 'SV-227627r603266_rule'
  tag stig_id: 'GEN001361'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29777r488442_fix'
  tag 'documentable'
  tag legacy: ['V-22318', 'SV-26388']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
