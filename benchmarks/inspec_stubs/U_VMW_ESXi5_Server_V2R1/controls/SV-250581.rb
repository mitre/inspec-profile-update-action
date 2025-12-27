control 'SV-250581' do
  title 'The system must be checked for extraneous device files at least weekly.'
  desc 'If an unauthorized device is allowed to exist on the system, there is the possibility the system may perform unauthorized operations.'
  desc 'check', 'Ask the SA if the system is checked for extraneous device files on a weekly basis. To manually perform the check, disable lock down mode, enable the ESXi Shell, and execute the following command:
# find / \\( -type b -o -type c \\) -exec ls -lL {} \\;

Re-enable lock down mode.

If no automated or manual process is in place, this is a finding.'
  desc 'fix', 'Configure the system to check for extraneous device files on a weekly basis.   Refer to the Check Content section above for the basic command structure to search the file system. Additionally, ensure persistence of the command output by storing results to a target located on persistent storage.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54016r798740_chk'
  tag severity: 'low'
  tag gid: 'V-250581'
  tag rid: 'SV-250581r798742_rule'
  tag stig_id: 'GEN002260-ESXI5-000047'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53970r798741_fix'
  tag 'documentable'
  tag legacy: ['V-39424', 'SV-51282']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
