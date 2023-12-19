control 'SV-253095' do
  title 'TOSS must enable the "SELinux" targeted policy.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', %q(Ensure TOSS  verifies correct operation of all security functions.

Check if "SELinux" is active and is enforcing the targeted policy with the following command:

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
Max kernel policy version: 33

If the "Loaded policy name" is not set to "targeted", this is a finding.

Verify that the /etc/selinux/config file is configured to the "SELINUXTYPE" to "targeted":

$ sudo grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'
SELINUXTYPE = targeted

If no results are returned or "SELINUXTYPE" is not set to "targeted", this is a finding.)
  desc 'fix', 'Configure the operating system to verify correct operation of all security functions.

Set the "SELinuxtype" to the "targeted" policy by modifying the "/etc/selinux/config" file to have the following line:

SELINUXTYPE=targeted

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56548r824955_chk'
  tag severity: 'medium'
  tag gid: 'V-253095'
  tag rid: 'SV-253095r824957_rule'
  tag stig_id: 'TOSS-04-040510'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-56498r824956_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
