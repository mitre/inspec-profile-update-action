control 'SV-217149' do
  title 'The SUSE operating system must notify the System Administrator (SA) when AIDE discovers anomalies in the operation of any security functions.'
  desc 'If anomalies are not acted on, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.'
  desc 'check', 'Verify the SUSE operating system notifies the SA when AIDE discovers anomalies in the operation of any security functions.

Check to see if the aide cron job sends an email when executed with the following command:

     # sudo crontab -l 
     0 0 * * 6 /usr/sbin/aide --check | /var/spool/mail -s "aide integrity check run for <system name>" root@notareal.email

If a "crontab" entry does not exist, check the cron directories for a script that runs the file integrity application and is configured to execute a binary to send an email:

     # ls -al /etc/cron.daily /etc/cron.weekly

If a cron job is not configured to execute a binary to send an email (such as "/usr/bin/mail"), this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to notify the SA when AIDE discovers anomalies in the operation of any security functions.

Add following command to a cron job replacing the "[E-MAIL]" parameter with a proper email address for the SA:

     /usr/sbin/aide --check | /var/spool/mail -s "aide integrity check run for <system name>" root@notareal.email'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18377r880932_chk'
  tag severity: 'medium'
  tag gid: 'V-217149'
  tag rid: 'SV-217149r880934_rule'
  tag stig_id: 'SLES-12-010510'
  tag gtitle: 'SRG-OS-000447-GPOS-00201'
  tag fix_id: 'F-18375r880933_fix'
  tag 'documentable'
  tag legacy: ['V-77153', 'SV-91849']
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
