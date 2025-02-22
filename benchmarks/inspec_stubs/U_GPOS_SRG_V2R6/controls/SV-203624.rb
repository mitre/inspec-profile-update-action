control 'SV-203624' do
  title 'The operating system must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify the operating system maps the authenticated identity to the user or group account for PKI-based authentication. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to map the authenticated identity to the user or group account for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3749r557596_chk'
  tag severity: 'medium'
  tag gid: 'V-203624'
  tag rid: 'SV-203624r557598_rule'
  tag stig_id: 'SRG-OS-000068-GPOS-00036'
  tag gtitle: 'SRG-OS-000068'
  tag fix_id: 'F-3749r557597_fix'
  tag 'documentable'
  tag legacy: ['SV-70947', 'V-56687']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
