control 'SV-214347' do
  title 'The Apache web server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the Apache web server.'
  desc 'To make certain that the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism needs to be able to allocate log record storage capacity. 

The task of allocating log record storage capacity is usually performed during initial installation of the logging mechanism. The System Administrator will usually coordinate the allocation of physical drive space with the web server administrator along with the physical location of the partition and disk. Refer to NIST SP 800-92 for specific requirements on log rotation and storage dependent on the impact of the web server.'
  desc 'check', 'Work with SIEM administrator to determine log storage capacity. 

If there is no setting within a SIEM to accommodate enough a large logging capacity, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to determine if the SIEM is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the Apache web server.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15559r277544_chk'
  tag severity: 'medium'
  tag gid: 'V-214347'
  tag rid: 'SV-214347r505936_rule'
  tag stig_id: 'AS24-W1-000710'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag fix_id: 'F-15557r277545_fix'
  tag 'documentable'
  tag legacy: ['SV-102535', 'V-92447']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
