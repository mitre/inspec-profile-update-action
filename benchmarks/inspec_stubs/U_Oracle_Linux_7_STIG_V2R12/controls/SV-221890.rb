control 'SV-221890' do
  title 'The Oracle Linux operating system must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.'
  desc 'When an NFS server is configured to use RPCSEC_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request.'
  desc 'check', 'Verify "AUTH_GSS" is being used to authenticate NFS mounts.

To check if the system is importing an NFS file system, look for any entries in the "/etc/fstab" file that have a file system type of "nfs" with the following command:

# cat /etc/fstab | grep nfs
192.168.21.5:/mnt/export /data1 nfs4 rw,sync ,soft,sec=krb5:krb5i:krb5p

If the system is mounting file systems via NFS and has the sec option without the "krb5:krb5i:krb5p" settings, the "sec" option has the "sys" setting, or the "sec" option is missing, this is a finding.'
  desc 'fix', 'Update the "/etc/fstab" file so the option "sec" is defined for each NFS mounted file system and the "sec" option does not have the "sys" setting. 

Ensure the "sec" option is defined as "krb5:krb5i:krb5p".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23605r419742_chk'
  tag severity: 'medium'
  tag gid: 'V-221890'
  tag rid: 'SV-221890r603260_rule'
  tag stig_id: 'OL07-00-040750'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23594r419743_fix'
  tag 'documentable'
  tag legacy: ['V-99519', 'SV-108623']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
