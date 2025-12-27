control 'SV-223584' do
  title 'ACF2 system administrator must develop a procedure to disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Ask the system administrator for the procedure to disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.

If there is no procedure this is a finding.'
  desc 'fix', 'Develop a procedure to disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25257r500887_chk'
  tag severity: 'medium'
  tag gid: 'V-223584'
  tag rid: 'SV-223584r533198_rule'
  tag stig_id: 'ACF2-OS-002470'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-25245r500888_fix'
  tag 'documentable'
  tag legacy: ['SV-106977', 'V-97873']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
