control 'SV-70971' do
  title 'The operating system must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57281r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56711'
  tag rid: 'SV-70971r1_rule'
  tag stig_id: 'SRG-OS-000461-GPOS-00205'
  tag gtitle: 'SRG-OS-000461-GPOS-00205'
  tag fix_id: 'F-61607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
