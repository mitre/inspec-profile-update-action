control 'SV-251701' do
  title 'The Oracle Linux operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to the Oracle Linux operating system performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:

$ sudo rpm -q aide

aide-0.15.1-13.0.1.el7_9.1.x86_64

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.'
  desc 'fix', 'Install the AIDE package by running the following command:

$ sudo yum install aide'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-55138r860889_chk'
  tag severity: 'medium'
  tag gid: 'V-251701'
  tag rid: 'SV-251701r860890_rule'
  tag stig_id: 'OL07-00-020029'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-55092r809182_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
