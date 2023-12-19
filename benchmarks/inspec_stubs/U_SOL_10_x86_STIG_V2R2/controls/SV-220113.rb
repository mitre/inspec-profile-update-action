control 'SV-220113' do
  title 'The Samba Web Administration Tool (SWAT) must be restricted to the local host or require SSL.'
  desc 'SWAT is a tool used to configure Samba. As it modifies Samba configuration, which can impact system security, it must be protected from unauthorized access. SWAT authentication may involve the root password, which must be protected by encryption when traversing the network.

Restricting access to the local host allows for the use of SSH TCP forwarding, if configured, or administration by a web browser on the local system.'
  desc 'check', 'Verify the SWAT daemon is running under inetd.

# svcs swat

If SWAT is disabled or not installed, this is not applicable.

Verify that TCP_wrappers is enabled for the SWAT daemon.

# inetadm -l swat | grep tcp_wrappers

If the tcp_wrappers value is unset or is set to FALSE, this is a finding.

Verify access to the SWAT daemon is limited to localhost through the use of TCP_Wrappers.

# more /etc/hosts.allow
# more /etc/hosts.deny

If the hosts.allow and hosts.deny access control files are configured such that remote access to SWAT is enabled, this is a finding.

Ask the SA if SSH port forwarding is used to enable remote access to SWAT. If it is, this is not a finding.  If all access to SWAT is via localhost using a local web browser, this is not a finding.'
  desc 'fix', 'Enable tcp_wrappers for the SWAT daemon.
# inetadm -m swat tcp_wrappers=true
  OR
# inetadm -M tcp_wrappers=true
Relfresh the inetd daemon.
# svcadm refresh inetd

Configure the hosts.allow and hosts.deny files to limit access to SWAT to localhost.
Example:
# echo ALL: ALL >> /etc/hosts.deny
# echo swat: localhost >> /etc/hosts.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36430r602893_chk'
  tag severity: 'medium'
  tag gid: 'V-220113'
  tag rid: 'SV-220113r603266_rule'
  tag stig_id: 'GEN006080'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-36394r602894_fix'
  tag 'documentable'
  tag legacy: ['V-1026', 'SV-42313']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
