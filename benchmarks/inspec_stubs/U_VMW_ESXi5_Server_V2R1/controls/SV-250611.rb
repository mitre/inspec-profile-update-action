control 'SV-250611' do
  title 'The system must be configured to only boot from the system boot device.'
  desc 'The ability to boot from removable media is the same as being able to boot into single user or maintenance mode without a password. This ability could allow a malicious user to boot the system and perform changes possibly compromising or damaging the system. It could also allow the system to be used for malicious purposes by a malicious anonymous user.'
  desc 'check', "Note: Checking a system's BIOS is vendor and hardware dependent. To verify media boot options: Interrupt the host computer's boot process and enter the BIOS menu. Inspect the menu option for boot order.

If any media other than the ESXi boot disk is listed as a boot option, this is a finding."
  desc 'fix', "Note: Checking a system's BIOS is vendor and hardware dependent. To ensure media boot options: Interrupt the host computer's boot process and enter the BIOS menu.  Inspect the menu option for boot order. Remove all boot media options except for ESXi.  Save the change and exit to verify the boot cycle."
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54046r798830_chk'
  tag severity: 'high'
  tag gid: 'V-250611'
  tag rid: 'SV-250611r798832_rule'
  tag stig_id: 'GEN008600-ESXI5-000050'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54000r798831_fix'
  tag 'documentable'
  tag legacy: ['V-39384', 'SV-51242']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
