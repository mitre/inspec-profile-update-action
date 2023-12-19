control 'SV-234864' do
  title 'The SUSE operating system must notify the System Administrator (SA) when Advanced Intrusion Detection Environment (AIDE) discovers anomalies in the operation of any security functions.'
  desc 'If anomalies are not acted on, security functions may fail to secure the system. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.'
  desc 'check', 'Verify the SUSE operating system notifies the SA when AIDE discovers anomalies in the operation of any security functions.

Check to see if the aide cron job sends an email when executed with the following command:

     > grep -i "aide" /etc/cron.*/aide 
     0 0 * * * /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

If the "aide" file does not exist under the "/etc/cron" directory structure or the cron job is not configured to execute a binary to send an email (such as "/bin/mail"), this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to notify the SA when AIDE discovers anomalies in the operation of any security functions.

Create the aide crontab file in "/etc/cron.daily" and add following command replacing the "[E-MAIL]" parameter with a proper email address for the SA:

     0 0 * * * /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

Note: Per requirement SLES-15-010418, the "mailx" package must be installed on the system to enable email functionality.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38052r902852_chk'
  tag severity: 'medium'
  tag gid: 'V-234864'
  tag rid: 'SV-234864r902854_rule'
  tag stig_id: 'SLES-15-010570'
  tag gtitle: 'SRG-OS-000447-GPOS-00201'
  tag fix_id: 'F-38015r902853_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
