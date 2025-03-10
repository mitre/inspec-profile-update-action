control 'SV-207673' do
  title 'The ESXi host must enable Secure Boot.'
  desc 'Secure Boot is a protocol of UEFI firmware that ensures the integrity of the boot process from hardware up through to the OS. Secure Boot for ESXi requires support from the firmware and it requires that all ESXi kernel modules, drivers, and VIBs be signed by VMware or a partner subordinate.'
  desc 'check', 'Temporarily enable SSH, connect to the ESXi host and run the following command:

/usr/lib/vmware/secureboot/bin/secureBoot.py -s

If the output is not Enabled, this is a finding.'
  desc 'fix', 'Temporarily enable SSH, connect to the ESXi host and run the following command:

/usr/lib/vmware/secureboot/bin/secureBoot.py -c

If the output indicates that Secure Boot cannot be enabled, correct the discrepancies and try again. If the discrepancies cannot be rectified this finding is downgraded to a CAT III.

Consult your vendor documentation and boot the host into BIOS setup mode. Enable UEFI boot mode and Secure Boot. Restart the host.

Temporarily enable SSH, connect to the ESXi host and run the following command to verify that Secure Boot is enabled:

/usr/lib/vmware/secureboot/bin/secureBoot.py -s'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7928r364418_chk'
  tag severity: 'medium'
  tag gid: 'V-207673'
  tag rid: 'SV-207673r388482_rule'
  tag stig_id: 'ESXI-65-000076'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7928r364419_fix'
  tag 'documentable'
  tag legacy: ['SV-104317', 'V-94487']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
