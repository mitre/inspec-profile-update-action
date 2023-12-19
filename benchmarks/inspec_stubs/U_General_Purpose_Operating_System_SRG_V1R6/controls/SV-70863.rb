control 'SV-70863' do
  title 'The operating system must generate audit records for all kernel module load, unload, and restart actions, and also for all program initiations.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records for all kernel module load, unload, and restart actions, and also for all program initiations. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for all kernel module load, unload, and restart actions, and also for all program initiations.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57173r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56603'
  tag rid: 'SV-70863r1_rule'
  tag stig_id: 'SRG-OS-000477-GPOS-00222'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-61499r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
