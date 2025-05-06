control 'SV-45967' do
  title 'The system must use and update a virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration by computer viruses and to limit their spread through intermediate systems. 

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Check for the existence of a virus scan tool to be executed daily in the cron file:

# crontab -l

With the assistance of the system administrator, ensure the virus definition signature files are not older than seven (7) days.

If a virus scanner is not being run daily or the virus definitions are older than seven (7) days, this is a finding.'
  desc 'fix', 'Install a virus scan tool.

Ensure the virus signature definition files are no older than seven (7) days.

Ensure the command line virus scan tool is run on a regular basis using a utility, such as cron.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43249r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12765'
  tag rid: 'SV-45967r2_rule'
  tag stig_id: 'GEN006640'
  tag gtitle: 'GEN006640'
  tag fix_id: 'F-39332r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
