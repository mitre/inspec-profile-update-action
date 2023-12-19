control 'SV-218290' do
  title 'The /etc/nsswitch.conf file must not have an extended ACL.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', "Verify /etc/nsswitch.conf has no extended ACL.

# ls -l /etc/nsswitch.conf

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19765r561659_chk'
  tag severity: 'medium'
  tag gid: 'V-218290'
  tag rid: 'SV-218290r603259_rule'
  tag stig_id: 'GEN001374'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19763r561660_fix'
  tag 'documentable'
  tag legacy: ['V-22330', 'SV-64545']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
