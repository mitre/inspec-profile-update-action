control 'SV-246964' do
  title 'ONTAP must be configured to send audit log data to a central log server.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Use "cluster log-forwarding show" to see if audit logs are being sent to a remote logging server.

Sample output from the command:

                                                                                           Verify   Syslog
Destination Host         Port   Protocol                   Server   Facility
------------------------ ------ ----------------------- --------  --------
192.168.0.1                     514    udp-unencrypted false       user

If no remote logging servers are listed, this is a finding.'
  desc 'fix', 'Configure ONTAP for remote syslogging with "cluster log-forwarding create -destination <hostname_or_ip_address>".'
  impact 0.7
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50396r860697_chk'
  tag severity: 'high'
  tag gid: 'V-246964'
  tag rid: 'SV-246964r860698_rule'
  tag stig_id: 'NAOT-SI-000001'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-50350r769223_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
