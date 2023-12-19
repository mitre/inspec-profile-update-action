control 'SV-254226' do
  title 'Nutanix AOS must be configured to restrict public directories.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Confirm Nutanix AOS provides that all public directories are owned by root or a system account with the following command:

$ sudo find / -type d -perm -0002 -exec ls -lLd {} \\;
drwxrwxrwt. 2 root root 40 Jun  4 15:21 /dev/mqueue
drwxrwxrwt. 2 root root 40 Jun  4 15:21 /dev/shm
drwxrwxrwt. 7 root root 4096 Jul 28 15:37 /tmp

If any of the returned directories are not owned by root or a system account, this is a finding.

Determine that all world-writable directories have the sticky bit set by running the following command:

$ sudo find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null
drwxrwxrwxt 7 root root 4096 Jul 26 11:19 /tmp

If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding.'
  desc 'fix', 'Configure all public directories to be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources.

Set the owner of all public directories as root or a system account using the command, replace "[Public Directory]" with any directory path not owned by root or a system account:

$ sudo chown root [Public Directory]

Set the sticky bit on all world-writable directories using the command, replace "[World-Writable Directory]" with any directory path missing the sticky bit:

$ sudo chmod 1777 [World-Writable Directory]'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57711r846764_chk'
  tag severity: 'medium'
  tag gid: 'V-254226'
  tag rid: 'SV-254226r846766_rule'
  tag stig_id: 'NUTX-OS-001490'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-57662r846765_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
