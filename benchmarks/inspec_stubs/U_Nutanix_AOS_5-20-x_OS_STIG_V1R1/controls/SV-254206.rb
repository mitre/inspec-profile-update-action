control 'SV-254206' do
  title 'Nutanix AOS must be configured to disable USB mass storage devices.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, devices such as flash drives, external storage, and printers.'
  desc 'check', 'Confirm Nutanix AOS is configured to disable USB mass storage devices.

$ sudo grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#"
install usb-storage /bin/true

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify the operating system disables the ability to use USB mass storage devices.
Determine if USB mass storage is disabled with the following command:

$ sudo grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#"
blacklist usb-storage

If the command does not return any output or the output is not "blacklist usb-storage", and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the system to disable USB mass storage and blacklist from executing by running the following command:

$ sudo salt-call state.sls security/CVM/modprobeCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57691r846704_chk'
  tag severity: 'medium'
  tag gid: 'V-254206'
  tag rid: 'SV-254206r846706_rule'
  tag stig_id: 'NUTX-OS-001210'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-57642r846705_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
