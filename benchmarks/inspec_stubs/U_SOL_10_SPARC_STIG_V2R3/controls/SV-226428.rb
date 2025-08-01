control 'SV-226428' do
  title 'The limitpriv zone option must be set to the vendor default or less permissive.'
  desc 'Solaris zones can be assigned privileges generally reserved for the global zone using the limitpriv zone option.  Any privilege assignments in excess of the vendor defaults may provide the ability for a non-global zone to compromise the global zone.'
  desc 'check', 'If the system is not a global zone, this vulnerability is not applicable.
List the non-global zones on the system.
# zoneadm list -vi
List the configuration for each zone.
# zonecfg -z <zone> info
Check the limitpriv lines.  If a line set other than default, this is a finding.  If limitpriv is not set, this is not a finding.'
  desc 'fix', 'Change the limitpriv setting to default.
# zonecfg -z <zone> set limitpriv=default'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28589r482645_chk'
  tag severity: 'medium'
  tag gid: 'V-226428'
  tag rid: 'SV-226428r603265_rule'
  tag stig_id: 'GEN000000-SOL00640'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28577r482646_fix'
  tag 'documentable'
  tag legacy: ['SV-27023', 'V-22608']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
