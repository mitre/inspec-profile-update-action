control 'SV-218286' do
  title 'The /etc/hosts file must not have an extended ACL.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', "Verify  /etc/hosts has no extended ACL.

# ls -l /etc/hosts

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /etc/hosts'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19761r568816_chk'
  tag severity: 'medium'
  tag gid: 'V-218286'
  tag rid: 'SV-218286r603259_rule'
  tag stig_id: 'GEN001369'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19759r568817_fix'
  tag 'documentable'
  tag legacy: ['V-22326', 'SV-64533']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
