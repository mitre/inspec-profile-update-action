control 'SV-207371' do
  title 'The VMM must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify the VMM maps the authenticated identity to the user or group account for PKI-based authentication.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to map the authenticated identity to the user or group account for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7628r365523_chk'
  tag severity: 'medium'
  tag gid: 'V-207371'
  tag rid: 'SV-207371r378736_rule'
  tag stig_id: 'SRG-OS-000068-VMM-000350'
  tag gtitle: 'SRG-OS-000068'
  tag fix_id: 'F-7628r365524_fix'
  tag 'documentable'
  tag legacy: ['SV-71189', 'V-56929']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
