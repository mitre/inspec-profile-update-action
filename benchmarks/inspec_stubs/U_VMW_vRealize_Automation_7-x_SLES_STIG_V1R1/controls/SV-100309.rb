control 'SV-100309' do
  title 'The SMTP service log files must be owned by root.'
  desc 'If the SMTP service log file is not owned by root, then unauthorized personnel may modify or delete the file to hide a system compromise.'
  desc 'check', 'Check the permissions on the mail log files:

# ls -la /var/log/mail
# ls -la /var/log/mail.info
# ls -la /var/log/mail.warn
# ls -la /var/log/mail.err

If any mail log file is not owned by "root", this is a finding.'
  desc 'fix', 'Change the ownership of the sendmail log files:

# chown root <sendmail log file>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89351r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89659'
  tag rid: 'SV-100309r1_rule'
  tag stig_id: 'VRAU-SL-000600'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96401r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
