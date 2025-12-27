control 'SV-245568' do
  title 'The AIX /var/spool/cron/atjobs directory must have a mode of 0640 or less permissive.'
  desc "Incorrect permissions of the /var/spool/cron/atjobs directory could permit unauthorized users the ability to alter atjobs and run automated jobs as privileged users. Failure to set proper permissions of the /var/spool/cron/atjobs directory provides unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the mode of the /var/spool/cron/atjobs directory using command:

# ls -ld /var/spool/cron/atjobs 
drw-r----- 1 daemon daemon 993 Mar 11 07:04 /var/spool/cron/atjobs

If the directory has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the mode of the /var/spool/cron/atjobs directory:
# chmod 640 /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48847r755143_chk'
  tag severity: 'medium'
  tag gid: 'V-245568'
  tag rid: 'SV-245568r755145_rule'
  tag stig_id: 'AIX7-00-002149'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48802r755144_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
