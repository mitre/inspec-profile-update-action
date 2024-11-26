control 'SV-70875' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the audit system is configured to audit the loading and unloading of dynamic kernel modules. If it does not, this is a finding.'
  desc 'fix', 'Configure the audit system to audit the loading and unloading of dynamic kernel modules.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57185r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56615'
  tag rid: 'SV-70875r1_rule'
  tag stig_id: 'SRG-OS-000471-GPOS-00216'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-61511r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
