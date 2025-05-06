control 'SV-248549' do
  title 'OL 8 must have the "policycoreutils" package installed.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.'
  desc 'check', 'Verify the operating system has the "policycoreutils" package installed with the following command: 
 
$ sudo yum list installed policycoreutils 
 
policycoreutils.x86_64 2.9-3.el8 @anaconda 
 
If the "policycoreutils" package is not installed, this is a finding.'
  desc 'fix', 'Install the "policycoreutil" package, if it is not already installed, by running the following command: 
 
$ sudo yum install policycoreutils'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51983r779211_chk'
  tag severity: 'low'
  tag gid: 'V-248549'
  tag rid: 'SV-248549r779213_rule'
  tag stig_id: 'OL08-00-010171'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-51937r779212_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
