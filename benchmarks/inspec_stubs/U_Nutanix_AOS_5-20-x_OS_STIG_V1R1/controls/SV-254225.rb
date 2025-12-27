control 'SV-254225' do
  title 'Nutanix AOS must be configured to run SELinux Policies.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.'
  desc 'check', 'Nutanix AOS is configured by default to run SELinux Policies. Confirm Nutanix AOS has the policycoreutils package installed with the following command:

$ sudo yum list installed policycoreutils
Installed Packages
policycoreutils.x86_64                                                 2.5-34.el7                                                 @base

If the policycoreutils package is not installed, this is a finding.'
  desc 'fix', 'Configure the operating system to have the policycoreutils package installed with the following command:

$ sudo yum install policycoreutils'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57710r846761_chk'
  tag severity: 'medium'
  tag gid: 'V-254225'
  tag rid: 'SV-254225r846763_rule'
  tag stig_id: 'NUTX-OS-001480'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-57661r846762_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
