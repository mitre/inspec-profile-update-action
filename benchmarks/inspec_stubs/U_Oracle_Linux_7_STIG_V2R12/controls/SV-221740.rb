control 'SV-221740' do
  title 'The Oracle Linux operating system must be configured so that all system device files are correctly labeled to prevent unauthorized modification.'
  desc 'If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations.'
  desc 'check', 'Verify that all system device files are correctly labeled to prevent unauthorized modification.

List all device files on the system that are incorrectly labeled with the following commands:

Note: Device files are normally found under "/dev", but applications may place device files in other directories and may necessitate a search of the entire system.

#find /dev -context *:device_t:* \\( -type c -o -type b \\) -printf "%p %Z\\n"

#find /dev -context *:unlabeled_t:* \\( -type c -o -type b \\) -printf "%p %Z\\n"

Note: There are device files, such as "/dev/vmci", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the "device_t" label to operate. These device files are not a finding.

If there is output from either of these commands, other than already noted, this is a finding.'
  desc 'fix', 'Run the following command to determine which package owns the device file:

# rpm -qf <filename>

The package can be reinstalled from a yum repository using the command:

# sudo yum reinstall <packagename>

Alternatively, the package can be reinstalled from trusted media using the command:

# sudo rpm -Uvh <packagename>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23455r419292_chk'
  tag severity: 'medium'
  tag gid: 'V-221740'
  tag rid: 'SV-221740r603260_rule'
  tag stig_id: 'OL07-00-020900'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23444r419293_fix'
  tag 'documentable'
  tag legacy: ['V-99219', 'SV-108323']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
