control 'SV-234856' do
  title 'The SUSE operating system must disable the USB mass storage kernel module.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include but are not limited to such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify the SUSE operating system does not automount USB mass storage devices when connected to the host.

Check that "usb-storage" is blacklisted in the "/etc/modprobe.d/50-blacklist.conf" file with the following command:

> grep usb-storage /etc/modprobe.d/50-blacklist.conf
blacklist usb-storage

If nothing is output from the command, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to prevent USB mass storage devices from automounting when connected to the host.

Add or update the following line to the "/etc/modprobe.d/50-blacklist.conf" file:

blacklist usb-storage'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38044r618837_chk'
  tag severity: 'medium'
  tag gid: 'V-234856'
  tag rid: 'SV-234856r622137_rule'
  tag stig_id: 'SLES-15-010480'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-38007r618838_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
