control 'SV-38311' do
  title 'The /etc/resolv.conf file must be group-owned by root, bin, sys, or system.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Check the group ownership of the resolv.conf file.

Procedure:
# ls -lL /etc/resolv.conf

If the file is not group-owned by root, bin, sys, or other, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/resolv.conf file to root, bin, sys, or other.

Procedure:
# chgrp root /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36319r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22320'
  tag rid: 'SV-38311r1_rule'
  tag stig_id: 'GEN001363'
  tag gtitle: 'GEN001363'
  tag fix_id: 'F-31574r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
