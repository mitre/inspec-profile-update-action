control 'SV-26397' do
  title 'The /etc/resolv.conf file must have mode 0644 or less permissive.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions, such as time synchronization, centralized authentication, and remote system logging."
  desc 'fix', 'Change the mode of the /etc/resolv.conf file to 0644 or less permissive.

# chmod 0644 /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22321'
  tag rid: 'SV-26397r1_rule'
  tag stig_id: 'GEN001364'
  tag gtitle: 'GEN001364'
  tag fix_id: 'F-23588r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
