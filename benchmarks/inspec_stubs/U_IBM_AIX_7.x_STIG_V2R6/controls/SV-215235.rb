control 'SV-215235' do
  title 'AIX removable media, remote file systems, and any file system not containing approved device files must be mounted with the nodev option.'
  desc 'The nodev (or equivalent) mount option causes the system to not handle device files as system devices. This option must be used for mounting any file system not containing approved device files. Device files can provide direct access to system hardware and can compromise security if not protected.'
  desc 'check', 'Identify any file system mounted from removable media, network shares, or file systems not containing any approved device files:

# cat /etc/filesystems

/:

        dev             = /dev/hd4
        vfs             = jfs2
        log             = /dev/hd8
        mount           = automatic
        check           = false
        type            = bootfs
        vol             = root
        free            = true

/home:

        dev       = /dev/hd1
        vol       = "/home"
        mount     = true
        check     = true
        free      = false
        vfs       = jfs2
        log       = /dev/hd8

10.17.76.74:/opt/nfs /home/doejohn

        vfs             = nfs
        log             = /dev/hd8
        mount           = true
        options        = nodev 
        account         = false

If any file system mounted from removable media, network shares, or file systems not containing any approved device files is not using the "nodev" option, this is a finding.'
  desc 'fix', 'Edit "/etc/filesystems" and add the "options = nodev" to all entries for remote or removable media file systems, and file systems containing no approved device files.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16433r294156_chk'
  tag severity: 'medium'
  tag gid: 'V-215235'
  tag rid: 'SV-215235r508663_rule'
  tag stig_id: 'AIX7-00-001139'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16431r294157_fix'
  tag 'documentable'
  tag legacy: ['SV-101799', 'V-91701']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
