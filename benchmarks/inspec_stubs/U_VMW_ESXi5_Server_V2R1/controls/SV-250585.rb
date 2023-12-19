control 'SV-250585' do
  title 'The system must be checked weekly for unauthorized setgid files, as well as, unauthorized modification to authorized setgid files.'
  desc 'Files with the setgid bit set will allow anyone running these files to be temporarily assigned the GID of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs that allow reading and writing of files, or shell escapes.'
  desc 'check', 'Ask the SA if the system is checked for unauthorized setgid files on a weekly basis. To manually perform the check, disable lock down mode, enable the ESXi Shell, and execute the following command:
# find / -perm -2000 -exec ls -lL {} \\;

Re-enable lock down mode.

If no automated or manual process is in place, this is a finding.'
  desc 'fix', 'Configure the system to check for unauthorized setgid files on a weekly basis.   Refer to the Check Content section above for the basic command structure to search the file system. Additionally, ensure persistence of the command output by storing results to a target located on persistent storage.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54020r798752_chk'
  tag severity: 'medium'
  tag gid: 'V-250585'
  tag rid: 'SV-250585r798754_rule'
  tag stig_id: 'GEN002460-ESXI5-20047'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53974r798753_fix'
  tag 'documentable'
  tag legacy: ['V-39426', 'SV-51284']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
