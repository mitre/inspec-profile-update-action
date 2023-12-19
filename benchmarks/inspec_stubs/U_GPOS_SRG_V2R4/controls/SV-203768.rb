control 'SV-203768' do
  title 'The operating system must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records for privileged activities or other system-level access. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for privileged activities or other system-level access.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3893r375425_chk'
  tag severity: 'medium'
  tag gid: 'V-203768'
  tag rid: 'SV-203768r381475_rule'
  tag stig_id: 'SRG-OS-000471-GPOS-00215'
  tag gtitle: 'SRG-OS-000471'
  tag fix_id: 'F-3893r375426_fix'
  tag 'documentable'
  tag legacy: ['V-56617', 'SV-70877']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
