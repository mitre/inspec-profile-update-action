control 'SV-37307' do
  title 'The /etc/resolv.conf file must not have an extended ACL.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22322'
  tag rid: 'SV-37307r1_rule'
  tag stig_id: 'GEN001365'
  tag gtitle: 'GEN001365'
  tag fix_id: 'F-23589r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
