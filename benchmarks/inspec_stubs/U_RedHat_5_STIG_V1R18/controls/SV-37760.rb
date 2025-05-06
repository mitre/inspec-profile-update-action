control 'SV-37760' do
  title 'The system must use and update a DoD-approved virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.  

The virus scanning software should be configured to perform scans dynamically on accessed files.  If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Check for the existence of a cron job to execute a DoD-approved command-line scan tool daily. Other tools may be available but will have to be manually reviewed if they are installed. In addition, the definitions files should not be older than 7 days. 

Check if DoD-approved command-line scan tool is scheduled to run:
# grep [scan tool] /var/spool/cron/* /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/*

If a virus scanner is not being run daily and an exception has not been documented with the IAO, this is a finding.

Perform the following command to ensure the virus definition signature files are not older than 7 days.

# cd <scan tool install directory>
# ls -la *.dat

If the virus definitions are older than 7 days, this is a finding.'
  desc 'fix', 'Install a DoD-approved command-line virus scan tool, or an appropriate alternative. Ensure the virus signature definition files are no older than 7 days. Configure the system to run a virus scan on altered files dynamically or daily. If daily scans impede operations, justify, document, and obtain IAO approval for alternate scheduling.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36956r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12765'
  tag rid: 'SV-37760r2_rule'
  tag stig_id: 'GEN006640'
  tag gtitle: 'GEN006640'
  tag fix_id: 'F-32221r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
