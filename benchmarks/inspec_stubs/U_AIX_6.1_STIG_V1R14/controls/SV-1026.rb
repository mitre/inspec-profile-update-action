control 'SV-1026' do
  title 'The Samba Web Administration Tool (SWAT) must be restricted to the local host or require SSL.'
  desc 'SWAT is a tool used to configure Samba.  As it modifies Samba configuration, which can impact system security, it must be protected from unauthorized access.  SWAT authentication may involve the root password, which must be protected by encryption when traversing the network.

Restricting access to the local host allows for the use of SSH TCP forwarding, if configured, or administration by a web browser on the local system.'
  desc 'check', 'Check the system for an enabled SWAT service.

# grep -i swat /etc/inetd.conf

If SWAT is found enabled, it must be utilized with SSL to ensure a secure connection between the client and the server.  Ask the SA to identify the method used to provide SSL protection for the SWAT service.  Verify (or ask the SA to demonstrate) this configuration is effective by accessing SWAT using an HTTPS connection from a web browser.

If SWAT is found enabled and has no SSL protection, this is a finding.'
  desc 'fix', 'Disable SWAT (e.g., remove the "swat" line from inetd.conf or equivalent, and restart the service) or configure SSL protection for the SWAT service.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-2047r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1026'
  tag rid: 'SV-1026r2_rule'
  tag stig_id: 'GEN006080'
  tag gtitle: 'GEN006080'
  tag fix_id: 'F-1180r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBRP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
