control 'SV-227639' do
  title 'The /etc/nsswitch.conf file must not have an extended ACL.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Verify /etc/nsswitch.conf has no extended ACL.

Procedure:
# ls -l /etc/nsswitch.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29801r488477_chk'
  tag severity: 'medium'
  tag gid: 'V-227639'
  tag rid: 'SV-227639r603266_rule'
  tag stig_id: 'GEN001374'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29789r488478_fix'
  tag 'documentable'
  tag legacy: ['V-22330', 'SV-26422']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
