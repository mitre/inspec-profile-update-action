control 'SV-227667' do
  title 'Run control scripts must not execute world-writable programs or scripts.'
  desc 'World-writable files could be modified accidentally or maliciously to compromise system integrity.'
  desc 'check', %q(Check the permissions on the files or scripts executed from system startup scripts to see if they are world-writable.
Create a list of all potential run command level scripts.
# ls -l /etc/init.d/* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " "
OR
# ls -l /sbin/init.d/* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " "


Create a list of world writeable files.
# find / -perm -002 -type f >> worldWriteableFileList

Determine if any of the world writeable files in worldWriteableFileList are called from the run command level scripts. Note: Depending upon the number of scripts vs world writeable files, it may be easier to inspect the scripts manually.
# more `ls -l /etc/init.d/* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " "` 
OR
# more `ls -l /sbin/init.d/* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " "` 

If any system startup script executes any file or script that is world-writable, this is a finding.)
  desc 'fix', 'Remove the world-writable permission from programs or scripts executed by run control scripts.

Procedure:
# chmod o-w <program or script executed from run control script>'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29829r488567_chk'
  tag severity: 'high'
  tag gid: 'V-227667'
  tag rid: 'SV-227667r603266_rule'
  tag stig_id: 'GEN001640'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29817r488568_fix'
  tag 'documentable'
  tag legacy: ['V-910', 'SV-39810']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
