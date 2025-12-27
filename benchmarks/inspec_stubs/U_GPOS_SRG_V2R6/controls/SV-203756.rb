control 'SV-203756' do
  title 'The operating system must verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify the operating system verifies correct operation of all security functions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to verify correct operation of all security functions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3881r375389_chk'
  tag severity: 'medium'
  tag gid: 'V-203756'
  tag rid: 'SV-203756r851825_rule'
  tag stig_id: 'SRG-OS-000445-GPOS-00199'
  tag gtitle: 'SRG-OS-000445'
  tag fix_id: 'F-3881r375390_fix'
  tag 'documentable'
  tag legacy: ['SV-70979', 'V-56719']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
