control 'SV-226502' do
  title 'The /etc/resolv.conf file must be owned by root.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions, such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Verify the /etc/resolv.conf file is owned by root.

Procedure:
# ls -l /etc/resolv.conf
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/resolv.conf file to root.
# chown root /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28663r482894_chk'
  tag severity: 'medium'
  tag gid: 'V-226502'
  tag rid: 'SV-226502r603265_rule'
  tag stig_id: 'GEN001362'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28651r482895_fix'
  tag 'documentable'
  tag legacy: ['SV-26395', 'V-22319']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
