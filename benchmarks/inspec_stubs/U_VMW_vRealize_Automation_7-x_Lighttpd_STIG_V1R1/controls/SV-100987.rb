control 'SV-100987' do
  title 'Lighttpd must be configured to use syslog.'
  desc 'Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'accesslog.use-syslog' /opt/vmware/etc/lighttpd/lighttpd.conf | grep -v ^#

If the value for "accesslog.use-syslog" is not set to "enable" or is missing, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the lighttpd.conf file with the following: 

accesslog.use-syslog = "enable"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-90033r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90337'
  tag rid: 'SV-100987r1_rule'
  tag stig_id: 'VRAU-LI-000400'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-97079r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
