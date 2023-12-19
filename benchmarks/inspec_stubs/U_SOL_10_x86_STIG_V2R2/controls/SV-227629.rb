control 'SV-227629' do
  title 'The /etc/resolv.conf file must be group-owned by root, bin, or sys.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Check the group ownership of the resolv.conf file.

Procedure:
# ls -lL /etc/resolv.conf

If the file is not group owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/resolv.conf file to root, bin, or sys.

Procedure:
# chgrp root /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29791r488447_chk'
  tag severity: 'medium'
  tag gid: 'V-227629'
  tag rid: 'SV-227629r603266_rule'
  tag stig_id: 'GEN001363'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29779r488448_fix'
  tag 'documentable'
  tag legacy: ['V-22320', 'SV-39894']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
