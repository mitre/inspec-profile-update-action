control 'SV-239118' do
  title 'The Photon operating system must audit all account removal actions.'
  desc 'When operating system accounts are removed, user accessibility is affected. Accounts are used for identifying individual users or the operating system processes themselves. To detect and respond to events affecting user accessibility and system processing, operating systems must audit account removal actions.'
  desc 'check', 'At the command line, execute the following command:

# auditctl -l | grep -E "(userdel|groupdel)"

Expected result:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

If the output does not match the expected result, this is a finding.'
  desc 'fix', "At the command line, execute the following commands:

# echo '-w /usr/sbin/userdel -p x -k userdel' >> /etc/audit/rules.d/audit.STIG.rules
# echo '-w /usr/sbin/groupdel -p x -k groupdel' >> /etc/audit/rules.d/audit.STIG.rules
# /sbin/augenrules --load"
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42329r675160_chk'
  tag severity: 'medium'
  tag gid: 'V-239118'
  tag rid: 'SV-239118r675162_rule'
  tag stig_id: 'PHTN-67-000047'
  tag gtitle: 'SRG-OS-000241-GPOS-00091'
  tag fix_id: 'F-42288r675161_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
