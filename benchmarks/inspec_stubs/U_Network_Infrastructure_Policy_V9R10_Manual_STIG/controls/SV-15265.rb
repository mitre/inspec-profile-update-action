control 'SV-15265' do
  title 'All Internet-facing applications must be hosted in a DoD Demilitarized Zone (DMZ) Extension.'
  desc 'Without the protection of a DMZ, production networks will be prone to outside attacks as they are allowing externally accessible services to be accessed on the internal LAN.  This can cause many undesired consequences such as access to the entire network, Denial of Service attacks, or theft of sensitive information.'
  desc 'check', 'Review the network topology diagram and interview the ISSO to verify that all Internet-facing applications are hosted in a DoD DMZ Extension.

If there are any Internet-facing applications hosted in the enclave’s DMZ or private network, this is a finding.'
  desc 'fix', 'Implement and move internet facing applications logically to a DoD DMZ Extension.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-13707r5_chk'
  tag severity: 'medium'
  tag gid: 'V-14640'
  tag rid: 'SV-15265r4_rule'
  tag stig_id: 'NET0348'
  tag gtitle: 'Internet facing applications must be in a DoD DMZ Extension.'
  tag fix_id: 'F-14742r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
