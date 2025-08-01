control 'SV-239535' do
  title 'The SMTP service log files must be owned by root.'
  desc 'If the SMTP service log file is not owned by root, then unauthorized personnel may modify or delete the file to hide a system compromise.'
  desc 'check', 'Check the permissions on the mail log files:

# ls -la /var/log/mail
# ls -la /var/log/mail.info
# ls -la /var/log/mail.warn
# ls -la /var/log/mail.err

If any mail log file is not owned by "root", this is a finding.'
  desc 'fix', 'Change the ownership of the sendmail log files to "root":

# chown root <sendmail log file>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42768r662054_chk'
  tag severity: 'medium'
  tag gid: 'V-239535'
  tag rid: 'SV-239535r662056_rule'
  tag stig_id: 'VROM-SL-000580'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42727r662055_fix'
  tag 'documentable'
  tag legacy: ['SV-99191', 'V-88541']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
