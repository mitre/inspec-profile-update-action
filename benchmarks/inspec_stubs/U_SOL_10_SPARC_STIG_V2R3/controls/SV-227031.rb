control 'SV-227031' do
  title 'The /etc/news/hosts.nntp (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the hosts.nntp file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check /etc/news/hosts.nntp permissions.

# ls -lL /etc/news/hosts.nntp

If /etc/news/hosts.nntp has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/news/hosts.nntp file to 0600.

# chmod 0600 /etc/news/hosts.nntp'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29193r485447_chk'
  tag severity: 'medium'
  tag gid: 'V-227031'
  tag rid: 'SV-227031r854448_rule'
  tag stig_id: 'GEN006260'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29181r485448_fix'
  tag 'documentable'
  tag legacy: ['SV-4273', 'V-4273']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
