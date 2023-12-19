control 'SV-226504' do
  title 'The /etc/resolv.conf file must have mode 0644 or less permissive.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions, such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Check the mode of the /etc/resolv.conf file.

Procedure:
# ls -l /etc/resolv.conf
If the file mode is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/resolv.conf file to 0644 or less permissive.

# chmod 0644 /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28665r482900_chk'
  tag severity: 'medium'
  tag gid: 'V-226504'
  tag rid: 'SV-226504r603265_rule'
  tag stig_id: 'GEN001364'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28653r482901_fix'
  tag 'documentable'
  tag legacy: ['V-22321', 'SV-26397']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
