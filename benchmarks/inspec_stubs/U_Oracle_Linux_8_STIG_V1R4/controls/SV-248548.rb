control 'SV-248548' do
  title 'OL 8 must use a Linux Security Module configured to enforce limits on system services.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.  
 
Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. 
 
This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify the operating system verifies correct operation of all security functions.

Check if "SELinux" is in "Enforcing" mode with the following command:

$ getenforce
Enforcing

If "SELinux" is not in "Enforcing" mode, this is a finding.'
  desc 'fix', 'Configure OL 8 to verify correct operation of all security functions.

Set "SELinux" to "Enforcing" mode by modifying the "/etc/selinux/config" file with the following line:

SELINUX=enforcing

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51982r779208_chk'
  tag severity: 'medium'
  tag gid: 'V-248548'
  tag rid: 'SV-248548r779210_rule'
  tag stig_id: 'OL08-00-010170'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-51936r779209_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
