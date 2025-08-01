control 'SV-219343' do
  title 'The Ubuntu operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to the Ubuntu operating system performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:

# sudo dpkg -l | grep aide

aide/xenial,now 0.16~a2.git20130520-3 amd64 [installed]

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.'
  desc 'fix', 'Install the AIDE package by running the following command:

# sudo apt-get install aide'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21068r305357_chk'
  tag severity: 'medium'
  tag gid: 'V-219343'
  tag rid: 'SV-219343r853402_rule'
  tag stig_id: 'UBTU-18-010515'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-21067r305358_fix'
  tag 'documentable'
  tag legacy: ['V-100907', 'SV-110011']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
