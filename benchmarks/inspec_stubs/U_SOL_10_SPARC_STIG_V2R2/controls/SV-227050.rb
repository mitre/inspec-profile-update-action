control 'SV-227050' do
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled or not installed unless required.'
  desc 'The Reliable Datagram Sockets (RDS) protocol is a relatively new protocol developed by Oracle for communication between the nodes of a cluster.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.

'
  desc 'check', 'Ask the SA if RDS is required by application software running on the system.  If so, this is not applicable.

Verify the RDS protocol handler is not installed.
# pkginfo | grep SUNWrds
If no results are returned, this is not a finding.

Verify the RDS protocol handler is prevented from dynamic loading.
# grep "exclude: rds" /etc/system
If no result is returned, this is a finding.'
  desc 'fix', 'Remove the RDS protocol handler package.
# pkgrm SUNWrds

OR

Prevent the RDS protocol handler from dynamic loading.
# echo "exclude: rds" >> /etc/system'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29212r485519_chk'
  tag severity: 'medium'
  tag gid: 'V-227050'
  tag rid: 'SV-227050r603265_rule'
  tag stig_id: 'GEN007480'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-29200r485520_fix'
  tag satisfies: ['SRG-OS-000096', 'SRG-OS-000510']
  tag 'documentable'
  tag legacy: ['V-22530', 'SV-26894']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
