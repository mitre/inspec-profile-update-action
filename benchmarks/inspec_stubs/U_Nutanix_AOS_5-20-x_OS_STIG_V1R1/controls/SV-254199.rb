control 'SV-254199' do
  title 'Nutanix AOS must be configured with nodev, nosuid, and noexec options for /dev/shm.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system-level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'Confirm Nutanix AOS that "nodev","nosuid", and "noexec" options are configured for /dev/shm:

$ cat /etc/fstab | grep /dev/shm
tmpfs		/dev/shm	tmpfs	defaults,size=512m,noexec,rw,seclabel,nosuid,nodev	0 0

If /dev/shm is mounted without secure options "nodev", "nosuid", and "noexec", this is a finding.'
  desc 'fix', 'Configure Nutanix AOS so that /dev/shm is mounted with the "nodev", "nosuid", and "noexec" options by adding /modifying the /etc/fstab with the following line:

tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57684r846683_chk'
  tag severity: 'medium'
  tag gid: 'V-254199'
  tag rid: 'SV-254199r846685_rule'
  tag stig_id: 'NUTX-OS-001120'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-57635r846684_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
