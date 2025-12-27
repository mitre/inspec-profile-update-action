control 'SV-35211' do
  title 'The Samba Web Administration Tool (SWAT) must be restricted to the local host or require SSL.'
  desc 'SWAT is a tool used to configure Samba.  As it modifies Samba configuration, which can impact system security, it must be protected from unauthorized access.  SWAT authentication may involve the root password, which must be protected by encryption when traversing the network.

Restricting access to the local host allows for the use of SSH TCP forwarding, if configured, or administration by a web browser on the local system.'
  desc 'check', 'Determine if the CIFS (HP SAMBA) bundle is installed (SWAT is included). 
# swlist -l bundle | egrep -i "CIFS-CLIENT|CIFS-SERVER"

If the HP bundle is not installed, this is not applicable.

If the HP bundle is installed, ask the SA if the Samba Web Administration Tool (SWAT) has been configured to use SSL.

If SWAT is not configured to use SSL, this is a finding.'
  desc 'fix', 'Disable SWAT. 
# chmod 0000 <path>/swat

OR

# rm -i <path>/swat'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36693r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1026'
  tag rid: 'SV-35211r1_rule'
  tag stig_id: 'GEN006080'
  tag gtitle: 'GEN006080'
  tag fix_id: 'F-32068r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBRP-1, ECCT-1, ECCT-2'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
