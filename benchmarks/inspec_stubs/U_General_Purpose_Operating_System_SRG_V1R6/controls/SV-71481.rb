control 'SV-71481' do
  title 'The operating system must audit all account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access.  One way to accomplish this is for the attacker to enable a new or disabled account.  Auditing account modification actions provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the operating system automatically audits account enabling actions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57221'
  tag rid: 'SV-71481r2_rule'
  tag stig_id: 'SRG-OS-000303-GPOS-00120'
  tag gtitle: 'SRG-OS-000303-GPOS-00120'
  tag fix_id: 'F-62141r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
