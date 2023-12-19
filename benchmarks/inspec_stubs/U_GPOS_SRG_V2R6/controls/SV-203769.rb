control 'SV-203769' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the audit system is configured to audit the loading and unloading of dynamic kernel modules. If it does not, this is a finding.'
  desc 'fix', 'Configure the audit system to audit the loading and unloading of dynamic kernel modules.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3894r375428_chk'
  tag severity: 'medium'
  tag gid: 'V-203769'
  tag rid: 'SV-203769r381475_rule'
  tag stig_id: 'SRG-OS-000471-GPOS-00216'
  tag gtitle: 'SRG-OS-000471'
  tag fix_id: 'F-3894r375429_fix'
  tag 'documentable'
  tag legacy: ['SV-70875', 'V-56615']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
