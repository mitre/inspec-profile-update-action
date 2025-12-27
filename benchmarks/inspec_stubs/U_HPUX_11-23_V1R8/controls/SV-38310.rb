control 'SV-38310' do
  title 'The /etc/resolv.conf file must be owned by root.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Verify the /etc/resolv.conf file is owned by root.
# ls -lL /etc/resolv.conf
If the file is not owned by root, this is a finding.'
  desc 'fix', 'As root, change the owner of the /etc/resolv.conf file to root.
# chown root /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36318r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22319'
  tag rid: 'SV-38310r1_rule'
  tag stig_id: 'GEN001362'
  tag gtitle: 'GEN001362'
  tag fix_id: 'F-31573r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
