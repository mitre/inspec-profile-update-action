control 'SV-204453' do
  title 'The Red Hat Enterprise Linux operating system must enable SELinux.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Per OPORD 16-0080, the preferred intrusion detection system is McAfee Host Intrusion Prevention System (HIPS) in conjunction with SELinux.  McAfee Endpoint Security for Linux (ENSL) is an approved alternative to McAfee Virus Scan Enterprise (VSE) and HIPS. For RHEL 7 systems, SELinux is an approved alternative to McAfee HIPS. Regardless of whether or not McAfee HIPS or ENSL is installed, SELinux is interoperable with both McAfee products and SELinux is still required.

Verify the operating system verifies correct operation of all security functions.

Check if "SELinux" is active and in "Enforcing" mode with the following command:

# getenforce
Enforcing

If "SELinux" is not active and not in "Enforcing" mode, this is a finding.'
  desc 'fix', 'Configure the operating system to verify correct operation of all security functions.

Set the "SELinux" status and the "Enforcing" mode by modifying the "/etc/selinux/config" file to have the following line:

SELINUX=enforcing

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-36343r602627_chk'
  tag severity: 'medium'
  tag gid: 'V-204453'
  tag rid: 'SV-204453r603261_rule'
  tag stig_id: 'RHEL-07-020210'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-36306r602628_fix'
  tag 'documentable'
  tag legacy: ['V-71989', 'SV-86613']
  tag cci: ['CCI-002696', 'CCI-002165']
  tag nist: ['SI-6 a', 'AC-3 (4)']
end
