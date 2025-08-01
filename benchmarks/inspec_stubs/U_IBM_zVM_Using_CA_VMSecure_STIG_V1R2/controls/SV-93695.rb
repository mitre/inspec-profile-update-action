control 'SV-93695' do
  title 'The IBM z/VM system administrator must develop and perform a procedure to validate the correct operation of security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Ask the system administrator (SA) if there is a documented procedure for validation of security functions on file with the ISSM/ISSO.

If there is none, this is a finding.

Ask for evidence that the procedures are performed.

If there is no evidentiary proof, this is a finding.'
  desc 'fix', 'Develop a procedure that validates all security functions.

Develop a log depicting date and time of validation signed by action official.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78577r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78989'
  tag rid: 'SV-93695r1_rule'
  tag stig_id: 'IBMZ-VM-002410'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85739r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
