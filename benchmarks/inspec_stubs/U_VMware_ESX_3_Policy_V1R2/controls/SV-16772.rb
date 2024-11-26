control 'SV-16772' do
  title 'Hash signatures for the /etc files are not reviewed monthly.'
  desc 'Several files within ESX Server should be checked for file system integrity periodically. These files have been deemed critical by VMware in maintaining file system integrity. System administrators must ensure these files have the correct permissions and have not been modified. To ensure integrity, system administrators will use a FIPS 140-2 hash algorithm to create signatures of these files and store them offline. Comparing these hash values periodically will verify the integrity of the files.'
  desc 'check', 'Ask the IAO/SA how often the hash signatures are reviewed.  If they are not reviewed at least monthly, this is a finding.


File Location	Permission
/etc/fstab	640
/etc/group	644
/etc/host.conf	640
/etc/hosts	640
/etc/hosts.allow	640
/etc/hosts.deny	640
/etc/logrotate.conf	640
/etc/logrotate.d/	700
/etc/modules.conf	640
/etc/motd	640
/etc/ntp	755
/etc/ntp.conf	644
/etc/pam.d/system-auth	644
/etc/profile	644
/etc/shadow	400
/etc/securetty	600
/etc/ssh/sshd_config	600
/etc/snmp	755
/etc/sudoers	440
/etc/vmware	755'
  desc 'fix', 'Review the hash signatures for the /etc files monthly.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16181r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15833'
  tag rid: 'SV-16772r1_rule'
  tag stig_id: 'ESX0380'
  tag gtitle: 'Hash signatures for /etc file not reviewed.'
  tag fix_id: 'F-15784r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
