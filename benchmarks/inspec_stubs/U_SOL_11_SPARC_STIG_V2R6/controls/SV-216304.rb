control 'SV-216304' do
  title 'Run control scripts must not execute world writable programs or scripts.'
  desc 'World writable files could be modified accidentally or maliciously to compromise system integrity.'
  desc 'check', %q(Check the permissions on the files or scripts executed from system startup scripts to see if they are world writable.

Create a list of all potential run command level scripts.

# ls -l /etc/init.d/* /etc/rc* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " "

Create a list of world writable files.

# find / -perm -002 -type f >> WorldWritableFileList

Determine if any of the world writeable files in "WorldWritableFileList" are called from the run command level scripts.

Note: Depending upon the number of scripts vs. world writable files, it may be easier to inspect the scripts manually.

# more `ls -l /etc/init.d/* /etc/rc* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " "`

If any system startup script executes any file or script that is world writable, this is a finding.)
  desc 'fix', 'Remove the world writable permission from programs or scripts executed by run control scripts.

Procedure:

# chmod o-w <program or script executed from run control script>'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17540r371000_chk'
  tag severity: 'medium'
  tag gid: 'V-216304'
  tag rid: 'SV-216304r603267_rule'
  tag stig_id: 'SOL-11.1-020350'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17538r371001_fix'
  tag 'documentable'
  tag legacy: ['SV-74267', 'V-59837']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
