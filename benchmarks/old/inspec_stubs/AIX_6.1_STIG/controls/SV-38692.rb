control 'SV-38692' do
  title 'The /etc/resolv.conf file must not have an extended ACL.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Verify /etc/resolv.conf has no extended ACL.
Check if extended permissions are disabled.

Procedure:

#aclget /etc/resolv.conf 
If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from /etc/resolv.conf file and disable extended permissions.

#acledit /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37006r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22322'
  tag rid: 'SV-38692r1_rule'
  tag stig_id: 'GEN001365'
  tag gtitle: 'GEN001365'
  tag fix_id: 'F-32269r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
