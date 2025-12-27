control 'SV-218478' do
  title 'Network interfaces must not be configured to allow user control.'
  desc 'Configuration of network interfaces should be limited to privileged users.  Manipulation of network interfaces may result in a Denial of Service or bypass of network security mechanisms.'
  desc 'check', "Check the system for user-controlled network interfaces.
# grep -l '^USERCTL=yes' /etc/sysconfig/network-scripts/ifcfg* 
If any results are returned, this is a finding."
  desc 'fix', 'Edit the configuration for the user-controlled interface and remove the "USERCTL=yes" configuration line or set to "USERCTL=no".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19953r562588_chk'
  tag severity: 'medium'
  tag gid: 'V-218478'
  tag rid: 'SV-218478r603259_rule'
  tag stig_id: 'GEN003581'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-19951r562589_fix'
  tag 'documentable'
  tag legacy: ['V-22408', 'SV-64443']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
