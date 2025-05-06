control 'SV-16783' do
  title 'Log file permissions have not been configured to restrict unauthorized users'
  desc 'It is critical to protect system log files from being modified or accessed by unauthorized individuals. Some logs may contain sensitive data that should only be available to the virtualization server administrator.'
  desc 'check', 'On the ESX Server service console review the following log file permissions.
For each file or folder perform the following:
# ls –lL /var/log 

OR 

# ls –lL /var/log/(directory)

Log Location	Permission
/var/log/boot.log	600
/var/log/cron	600
/var/log/dmesg	640
/var/log/initrdlogs/	600
/var/log/ksyms	600
/var/log/maillog	600
/var/log/messages	600
/var/log/oldconf/	700
/var/log/rpmpkgs	600
/var/log/secure	600
/var/log/spooler	600
/var/log/storageMonitor	600
/var/log/sudolog	600
/var/log/vmkernel	600
/var/log/vmkproxy	600
/var/log/vmksummary	600
/var/log/vmksummary.d/	600
/var/log/vmkwarning	600
/var/log/vmware/	700


If any of the directories or files do not match the table above, this is a finding.'
  desc 'fix', 'Restrict unauthorized users from log files.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16188r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15842'
  tag rid: 'SV-16783r1_rule'
  tag stig_id: 'ESX0430'
  tag gtitle: 'Log files are not restricted to unauthorized users'
  tag fix_id: 'F-15796r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
