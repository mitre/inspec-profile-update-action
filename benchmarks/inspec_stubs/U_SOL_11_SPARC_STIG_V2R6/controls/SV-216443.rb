control 'SV-216443' do
  title 'The system must implement non-executable program stacks.'
  desc 'A common type of exploit is the stack buffer overflow. An application receives, from an attacker, more data than it is prepared for and stores this information on its stack, writing beyond the space reserved for it. This can be designed to cause execution of the data written on the stack. One mechanism to mitigate this vulnerability is for the system to not allow the execution of instructions in sections of memory identified as part of the stack.'
  desc 'check', 'Determine the OS version you are currently securing.

# uname –v

If the OS version is 11.3 or newer, this check applies to all zones and relies on the "sxadm" command. Determine if the system implements non-executable program stacks.

# sxadm status -p nxstack | cut -d: -f2
enabled.all

If the command output is not "enabled.all", this is a finding.

For Solaris 11, 11.1, and 11.2, this check applies to the global zone only and the "/etc/system" file is inspected. Determine the zone that you are currently securing.

# zonename

If the command output is "global", determine if the system implements non-executable program stacks. 

# grep noexec_user_stack /etc/system

If the noexec_user_stack is not set to 1, this is a finding.'
  desc 'fix', 'The root role is required.

Determine the OS version you are currently securing.

# uname –v

If the OS version is 11.3 or newer, enable non-executable program stacks using the "sxadm" command.

# pfexec sxadm enable nxstack

For Solaris 11, 11.1, and 11.2, this action applies to the global zone only and the "/etc/system" file is updated. Determine the zone that you are currently securing.

# zonename

If the command output is "global", modify the "/etc/system" file.

# pfedit /etc/system 

add the line:

set noexec_user_stack=1

Solaris 11, 11.1, and 11.2 systems will need to be restarted for the setting to take effect.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17679r793027_chk'
  tag severity: 'medium'
  tag gid: 'V-216443'
  tag rid: 'SV-216443r793063_rule'
  tag stig_id: 'SOL-11.1-080020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17677r371418_fix'
  tag 'documentable'
  tag legacy: ['SV-60897', 'V-48025']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
