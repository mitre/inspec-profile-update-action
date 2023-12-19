control 'SV-216229' do
  title 'The operating system must employ PKI solutions at workstations, servers, or mobile computing devices on the network to create, manage, distribute, use, store, and revoke digital certificates.'
  desc 'Without the use of PKI systems to manage digital certificates, the operating system or other system components may be unable to securely communicate on a network or reliably verify the identity of a user via digital signatures.'
  desc 'check', 'The operator will ensure that a DoD approved PKI system is installed, configured, and properly operating. Ask the operator to document the PKI software installation and configuration.

If the operator is not able to provide a documented configuration for an installed PKI system or if the PKI system is not properly configured, maintained, or used, this is a finding.'
  desc 'fix', 'The operator will ensure that a DoD approved PKI software is installed and operating continuously.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17467r373069_chk'
  tag severity: 'medium'
  tag gid: 'V-216229'
  tag rid: 'SV-216229r603268_rule'
  tag stig_id: 'SOL-11.1-090115'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17465r373070_fix'
  tag 'documentable'
  tag legacy: ['SV-62549', 'V-49625']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
