control 'SV-16774' do
  title 'The setuid and setgid flags have been disabled.'
  desc 'During the ESX Server installation, several applications have the  setuid and setgid flags set by default. These applications are initiated by or through the service console. Some of them provide facilities required for correct operation of the ESX Server host. Others are optional, but can make maintaining and troubleshooting the ESX Server and network easier.  Disabling any of the required setgid or setuid applications will result in problems with ESX Server authentication and virtual machine operation; however optional setgid or setuid applications may be disabled.'
  desc 'check', 'All the following setuid applications should have the setuid bit configured so that normal users may run the application with raised privileges.  

To verify the setuid bit is set (s), perform the following on the ESX Server service console:

# find /sbin /usr/bin /bin /usr/lib/vmware/bin \\ /usr/lib/vmware/bin-debug/ /usr/sbin –perm -4000
pam_timestamp_check
pwdb_chkpwd
unix_chkpwd
crontab
passwd
su
vmkload_app
vmware-vmx
vmkload_app
vmware-vmx
vmware-authd

If the setuid bit is not set on these applications, this is a finding.

OR

# find /sbin –perm -4000 
pam_timestamp_check
pwdb_chkpwd
unix_chkpwd

# find /usr/bin –perm -4000
crontab
passwd

# find /bin –perm -4000
su

# find /usr/lib/vmware/bin/ -perm -4000
vmkload_app
vmware-vmx

# find /usr/lib/vmware/bin-debug/ -perm -4000
vmkload_app
vmware-vmx

# find /usr/sbin/ -perm -4000
vmware-authd

If the setuid bit is not set on these applications, this is a finding.'
  desc 'fix', 'Configure the setuid and setgid applications with the appropriate permissions.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16182r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15835'
  tag rid: 'SV-16774r1_rule'
  tag stig_id: 'ESX0390'
  tag gtitle: 'The setuid and setgid flags have been disabled.'
  tag fix_id: 'F-15785r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'IAAC-1, IAIA-1, IAIA-2'
end
