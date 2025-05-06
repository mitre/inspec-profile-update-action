control 'SV-203775' do
  title 'The operating system must generate audit records for all kernel module load, unload, and restart actions, and also for all program initiations.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records for all kernel module load, unload, and restart actions, and also for all program initiations. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for all kernel module load, unload, and restart actions, and also for all program initiations.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3900r375716_chk'
  tag severity: 'medium'
  tag gid: 'V-203775'
  tag rid: 'SV-203775r381493_rule'
  tag stig_id: 'SRG-OS-000477-GPOS-00222'
  tag gtitle: 'SRG-OS-000477'
  tag fix_id: 'F-3900r375717_fix'
  tag 'documentable'
  tag legacy: ['SV-70863', 'V-56603']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
