control 'SV-218282' do
  title 'The /etc/resolv.conf file must not have an extended ACL.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', "Verify /etc/resolv.conf has no extended ACL.
# ls -l /etc/resolv.conf

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19757r568729_chk'
  tag severity: 'medium'
  tag gid: 'V-218282'
  tag rid: 'SV-218282r603259_rule'
  tag stig_id: 'GEN001365'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19755r568730_fix'
  tag 'documentable'
  tag legacy: ['V-22322', 'SV-64513']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
