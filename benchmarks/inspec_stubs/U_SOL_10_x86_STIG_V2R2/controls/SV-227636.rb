control 'SV-227636' do
  title 'The /etc/nsswitch.conf file must be owned by root.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Verify the /etc/nsswitch.conf file is owned by root.

Procedure:
# ls -l /etc/nsswitch.conf
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/nsswitch.conf file to root.

# chown root /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29798r488468_chk'
  tag severity: 'medium'
  tag gid: 'V-227636'
  tag rid: 'SV-227636r603266_rule'
  tag stig_id: 'GEN001371'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29786r488469_fix'
  tag 'documentable'
  tag legacy: ['V-22327', 'SV-26417']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
