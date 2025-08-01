control 'SV-70885' do
  title 'The operating system must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to delete privileges occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56625'
  tag rid: 'SV-70885r1_rule'
  tag stig_id: 'SRG-OS-000466-GPOS-00210'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-61521r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
