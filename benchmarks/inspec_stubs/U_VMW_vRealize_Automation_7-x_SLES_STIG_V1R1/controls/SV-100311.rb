control 'SV-100311' do
  title 'The SMTP service log file must have mode 0644 or less permissive.'
  desc 'If the SMTP service log file is more permissive than 0644, unauthorized users may be allowed to change the log file.'
  desc 'check', 'Check the permissions on the mail log files:

# ls -la /var/log/mail
# ls -la /var/log/mail.info
# ls -la /var/log/mail.warn
# ls -la /var/log/mail.err

If the log file permissions are greater than "0644", this is a finding.'
  desc 'fix', 'Change the mode of the sendmail log files:

# chmod 0644 <sendmail log file>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89353r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89661'
  tag rid: 'SV-100311r1_rule'
  tag stig_id: 'VRAU-SL-000605'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96403r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
