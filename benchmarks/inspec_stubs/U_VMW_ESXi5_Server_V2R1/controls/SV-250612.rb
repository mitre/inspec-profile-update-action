control 'SV-250612' do
  title 'The system must not use removable media as the boot loader.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader.'
  desc 'check', "Note: Checking a system's BIOS is vendor and hardware dependent. To verify media boot options: Interrupt the host computer's boot process and enter the BIOS menu.  Inspect the menu option for boot order. 

If any media other than the ESXi boot disk is listed as a boot option, this is a finding."
  desc 'fix', "Note: Checking a system's BIOS is vendor and hardware dependent. To ensure media boot options: Interrupt the host computer's boot process and enter the BIOS menu. Inspect the menu option for boot order. Remove all boot media options except for ESXi. Save the change and exit to verify the boot cycle."
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54047r798833_chk'
  tag severity: 'high'
  tag gid: 'V-250612'
  tag rid: 'SV-250612r798835_rule'
  tag stig_id: 'GEN008640-ESXI5-000055'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54001r798834_fix'
  tag 'documentable'
  tag legacy: ['SV-51093', 'V-39277']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
