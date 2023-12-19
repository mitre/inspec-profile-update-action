control 'SV-227628' do
  title 'The /etc/resolv.conf file must be owned by root.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions, such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Verify the /etc/resolv.conf file is owned by root.

Procedure:
# ls -l /etc/resolv.conf
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/resolv.conf file to root.
# chown root /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29790r488444_chk'
  tag severity: 'medium'
  tag gid: 'V-227628'
  tag rid: 'SV-227628r603266_rule'
  tag stig_id: 'GEN001362'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29778r488445_fix'
  tag 'documentable'
  tag legacy: ['V-22319', 'SV-26395']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
