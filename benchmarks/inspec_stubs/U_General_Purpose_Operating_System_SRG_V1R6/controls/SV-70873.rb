control 'SV-70873' do
  title 'The operating system must generate audit records showing starting and ending time for user access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records showing starting and ending time for user access to the system. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records showing starting and ending time for user access to the system.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56613'
  tag rid: 'SV-70873r1_rule'
  tag stig_id: 'SRG-OS-000472-GPOS-00217'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-61509r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
