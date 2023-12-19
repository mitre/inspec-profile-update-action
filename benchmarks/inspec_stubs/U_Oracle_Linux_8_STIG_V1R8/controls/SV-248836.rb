control 'SV-248836' do
  title 'The OL 8 file system automounter must be disabled unless required.'
  desc 'Verify the operating system disables the ability to automount devices. 
 
Determine if automounter service is active with the following command: 
 
$ sudo systemctl status autofs 
 
autofs.service - Automounts filesystems on demand 
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled) 
Active: inactive (dead) 
 
If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'check', 'Verify the operating system disables the ability to automount devices. 
 
Determine if the automounter service is active with the following command: 
 
$ sudo systemctl status autofs 
 
autofs.service - Automounts filesystems on demand 
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled) 
Active: inactive (dead) 
 
If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the ability to automount devices. 
 
Turn off the automount service with the following commands: 
 
$ sudo systemctl stop autofs 
$ sudo systemctl disable autofs 
 
If "autofs" is required for Network File System (NFS), it must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52270r780072_chk'
  tag severity: 'medium'
  tag gid: 'V-248836'
  tag rid: 'SV-248836r780074_rule'
  tag stig_id: 'OL08-00-040070'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-52224r780073_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
