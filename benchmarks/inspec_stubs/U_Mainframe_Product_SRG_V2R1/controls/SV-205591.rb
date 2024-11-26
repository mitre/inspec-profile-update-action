control 'SV-205591' do
  title 'The Mainframe Product performing organization-defined security functions must verify correct operation of security functions.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Examine the installation, configuration, and product documentation.

If the Mainframe Product verification of the correct operation of security functions, which may include the valid connection to an external security manager (ESM), is not performed, this is a finding.'
  desc 'fix', 'If necessary, configure the Mainframe Product configuration and installation settings to perform verification of the correct operation of security functions.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5857r300000_chk'
  tag severity: 'medium'
  tag gid: 'V-205591'
  tag rid: 'SV-205591r851356_rule'
  tag stig_id: 'SRG-APP-000472-MFP-000370'
  tag gtitle: 'SRG-APP-000472'
  tag fix_id: 'F-5857r300001_fix'
  tag 'documentable'
  tag legacy: ['SV-82983', 'V-68493']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
