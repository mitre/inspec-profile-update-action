control 'SV-203773' do
  title 'The operating system must generate audit records for all direct access to the information system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records for all direct access to the information system. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for all direct access to the information system.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3898r375710_chk'
  tag severity: 'medium'
  tag gid: 'V-203773'
  tag rid: 'SV-203773r381487_rule'
  tag stig_id: 'SRG-OS-000475-GPOS-00220'
  tag gtitle: 'SRG-OS-000475'
  tag fix_id: 'F-3898r375711_fix'
  tag 'documentable'
  tag legacy: ['SV-70867', 'V-56607']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
