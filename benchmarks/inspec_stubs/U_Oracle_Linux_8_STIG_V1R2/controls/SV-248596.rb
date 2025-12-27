control 'SV-248596' do
  title 'OL 8 must enable the SELinux targeted policy.'
  desc 'Without verification of the security functions, they may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. 
 
This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', %q(Ensure the operating system verifies correct operation of all security functions. 
 
Verify that "SELinux" is active and is enforcing the targeted policy with the following command: 
 
$ sudo sestatus 
 
SELinux status: enabled 
SELinuxfs mount: /sys/fs/selinux 
SELinux root directory: /etc/selinux 
Loaded policy name: targeted 
Current mode: enforcing 
Mode from config file: enforcing 
Policy MLS status: enabled 
Policy deny_unknown status: allowed 
Memory protection checking: actual (secure) 
Max kernel policy version: 31 
 
If the "Loaded policy name" is not set to "targeted", this is a finding. 
 
Verify that the "/etc/selinux/config" file is configured to the "SELINUXTYPE" as "targeted": 
 
$ sudo grep -i "selinuxtype" /etc/selinux/config | grep -v '^#' 
 
SELINUXTYPE = targeted 
 
If no results are returned or "SELINUXTYPE" is not set to "targeted", this is a finding.)
  desc 'fix', 'Configure OL 8 to verify correct operation of all security functions. 
 
Set the "SELinuxtype" to the "targeted" policy by modifying the "/etc/selinux/config" file to have the following line: 
 
SELINUXTYPE=targeted 
 
A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52030r779352_chk'
  tag severity: 'medium'
  tag gid: 'V-248596'
  tag rid: 'SV-248596r779354_rule'
  tag stig_id: 'OL08-00-010450'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-51984r779353_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
