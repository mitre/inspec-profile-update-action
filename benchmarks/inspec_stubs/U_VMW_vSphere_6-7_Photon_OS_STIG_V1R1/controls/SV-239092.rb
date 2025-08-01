control 'SV-239092' do
  title 'The Photon operating system must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.

'
  desc 'check', 'At the command line, execute the following command:

# auditctl -l | grep chmod

Expected result:

-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -k perm_mod

-a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -k perm_mod

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the following lines:

-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -k perm_mod

At the command line, execute the following commands:

# /sbin/augenrules --load'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42303r675082_chk'
  tag severity: 'medium'
  tag gid: 'V-239092'
  tag rid: 'SV-239092r675084_rule'
  tag stig_id: 'PHTN-67-000020'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-42262r675083_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
