control 'SV-254237' do
  title 'Nutanix AOS must be configured to use SELinux Enforcing mode.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

'
  desc 'check', %q(Confirm Nutanix AOS verifies correct operation of all security functions.

$ sudo sestatus
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Max kernel policy version:      31

If the "Loaded policy name" is not set to "targeted", this is a finding.

Verify that the /etc/selinux/config file is configured to the "SELINUXTYPE" to "targeted":

$ sudo grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'
SELINUXTYPE = targeted

If no results are returned or "SELINUXTYPE" is not set to "targeted", this is a finding.)
  desc 'fix', 'Configure Nutanix AOS to verify correct operation of all security functions.

Set the "SELinux" status and the "Enforcing" mode by modifying the "/etc/selinux/config" file to have the following line:

SELINUX=enforcing

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57722r846797_chk'
  tag severity: 'medium'
  tag gid: 'V-254237'
  tag rid: 'SV-254237r846799_rule'
  tag stig_id: 'NUTX-OS-001610'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-57673r846798_fix'
  tag satisfies: ['SRG-OS-000445-GPOS-00199', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000447-GPOS-00201', 'SRG-OS-000134-GPOS-00068']
  tag 'documentable'
  tag cci: ['CCI-001084', 'CCI-002696', 'CCI-002699', 'CCI-002702']
  tag nist: ['SC-3', 'SI-6 a', 'SI-6 b', 'SI-6 d']
end
