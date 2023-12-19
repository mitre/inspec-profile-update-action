control 'SV-226505' do
  title 'The /etc/resolv.conf file must not have an extended ACL.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Verify /etc/resolv.conf has no extended ACL.
# ls -l /etc/resolv.conf
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28666r482903_chk'
  tag severity: 'medium'
  tag gid: 'V-226505'
  tag rid: 'SV-226505r603265_rule'
  tag stig_id: 'GEN001365'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28654r482904_fix'
  tag 'documentable'
  tag legacy: ['V-22322', 'SV-26402']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
