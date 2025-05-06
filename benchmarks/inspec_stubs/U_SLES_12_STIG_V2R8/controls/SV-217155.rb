control 'SV-217155' do
  title 'The SUSE operating system must disable the USB mass storage kernel module.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include but are not limited to such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify the SUSE operating system does not automount USB mass storage devices when connected to the host.

Check that "usb-storage" is blacklisted in the "/etc/modprobe.d/50-blacklist.conf" file with the following command:

# grep usb-storage /etc/modprobe.d/50-blacklist.conf
blacklist usb-storage

If nothing is output from the command, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to prevent USB mass storage devices from automounting when connected to the host.

Add or update the following line to the "/etc/modprobe.d/50-blacklist.conf" file:

blacklist usb-storage'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18383r369621_chk'
  tag severity: 'medium'
  tag gid: 'V-217155'
  tag rid: 'SV-217155r854091_rule'
  tag stig_id: 'SLES-12-010580'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-18381r369622_fix'
  tag 'documentable'
  tag legacy: ['SV-91861', 'V-77165']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
