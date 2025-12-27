control 'SV-70865' do
  title 'The operating system must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records for all account creations, modifications, disabling, and termination events. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for all account creations, modifications, disabling, and termination events.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57175r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56605'
  tag rid: 'SV-70865r1_rule'
  tag stig_id: 'SRG-OS-000476-GPOS-00221'
  tag gtitle: 'SRG-OS-000476-GPOS-00221'
  tag fix_id: 'F-61501r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
