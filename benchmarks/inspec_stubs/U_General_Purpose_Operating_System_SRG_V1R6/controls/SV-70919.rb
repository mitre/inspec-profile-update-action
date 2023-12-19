control 'SV-70919' do
  title 'The operating system must produce audit records containing the individual identities of group account users.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the individual identities of group users. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the actual account involved in the activity.'
  desc 'check', 'Verify the operating system produces audit records containing the individual identities of group account users. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing the individual identities of group account users.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56659'
  tag rid: 'SV-70919r1_rule'
  tag stig_id: 'SRG-OS-000042-GPOS-00021'
  tag gtitle: 'SRG-OS-000042-GPOS-00021'
  tag fix_id: 'F-61555r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
