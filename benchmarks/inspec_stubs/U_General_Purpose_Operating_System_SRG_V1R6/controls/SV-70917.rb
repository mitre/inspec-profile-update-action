control 'SV-70917' do
  title 'The operating system must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify the operating system generates audit records containing the full-text recording of privileged commands. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records containing the full-text recording of privileged commands.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56657'
  tag rid: 'SV-70917r1_rule'
  tag stig_id: 'SRG-OS-000042-GPOS-00020'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-61553r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
