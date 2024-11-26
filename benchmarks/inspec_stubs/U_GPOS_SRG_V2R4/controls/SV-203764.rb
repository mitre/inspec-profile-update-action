control 'SV-203764' do
  title 'The operating system must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to delete privileges occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3889r375413_chk'
  tag severity: 'medium'
  tag gid: 'V-203764'
  tag rid: 'SV-203764r381460_rule'
  tag stig_id: 'SRG-OS-000466-GPOS-00210'
  tag gtitle: 'SRG-OS-000466'
  tag fix_id: 'F-3889r375414_fix'
  tag 'documentable'
  tag legacy: ['SV-70885', 'V-56625']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
