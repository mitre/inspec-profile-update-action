control 'SV-26395' do
  title 'The /etc/resolv.conf file must be owned by root.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions, such as time synchronization, centralized authentication, and remote system logging."
  desc 'fix', 'Change the owner of the /etc/resolv.conf file to root.
# chown root /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22319'
  tag rid: 'SV-26395r1_rule'
  tag stig_id: 'GEN001362'
  tag gtitle: 'GEN001362'
  tag fix_id: 'F-23586r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
