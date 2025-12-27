control 'SV-70877' do
  title 'The operating system must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records for privileged activities or other system-level access. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for privileged activities or other system-level access.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56617'
  tag rid: 'SV-70877r1_rule'
  tag stig_id: 'SRG-OS-000471-GPOS-00215'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-61513r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
