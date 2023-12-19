control 'SV-206599' do
  title 'The DBMS must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', 'Review the network functions, ports, protocols, and services supported by the DBMS.

If any protocol is prohibited by the PPSM guidance and is enabled, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of disabling a network function, port, protocol, or service prohibited by the PPSM guidance.

Disable each prohibited network function, port, protocol, or service.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6859r291465_chk'
  tag severity: 'medium'
  tag gid: 'V-206599'
  tag rid: 'SV-206599r617447_rule'
  tag stig_id: 'SRG-APP-000383-DB-000364'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-6859r291466_fix'
  tag 'documentable'
  tag legacy: ['V-58133', 'SV-72563']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
