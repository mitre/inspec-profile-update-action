control 'SV-39894' do
  title 'The /etc/resolv.conf file must be group-owned by root, bin, or sys.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'fix', 'Change the group owner of the /etc/resolv.conf file to root, bin, or sys.

Procedure:
# chgrp root /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22320'
  tag rid: 'SV-39894r1_rule'
  tag stig_id: 'GEN001363'
  tag gtitle: 'GEN001363'
  tag fix_id: 'F-34051r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
