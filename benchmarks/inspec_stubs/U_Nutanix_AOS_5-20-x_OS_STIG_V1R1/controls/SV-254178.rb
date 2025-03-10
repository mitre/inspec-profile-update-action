control 'SV-254178' do
  title "Nutanix AOS must allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  desc 'To ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems must be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', %q(Confirm Nutanix AOS preconfigures storage for one week's worth of audit records, when audit records are not immediately sent to a central audit record facility.

$ sudo cat /boot/grub/grub.conf | grep audit_backlog_limit
audit_backlog_limit=8192

If the "audit_backlog_limit" entry does not equal "8192", is missing, or the line is commented out, this is a finding.)
  desc 'fix', 'As root, modify the /boot/grub/grub.conf file to include the following line:

audit_backlog_limit=8192'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57663r846620_chk'
  tag severity: 'medium'
  tag gid: 'V-254178'
  tag rid: 'SV-254178r846622_rule'
  tag stig_id: 'NUTX-OS-000760'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-57614r846621_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
