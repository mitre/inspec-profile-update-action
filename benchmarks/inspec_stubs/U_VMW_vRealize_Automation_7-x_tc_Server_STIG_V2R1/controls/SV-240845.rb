control 'SV-240845' do
  title 'tc Server ALL must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the web server.'
  desc 'In order to make certain that the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism needs to be able to allocate log record storage capacity. 

The task of allocating log record storage capacity is usually performed during initial installation of the logging mechanism. The system administrator will usually coordinate the allocation of physical drive space with the web server administrator along with the physical location of the partition and disk. Refer to NIST SP 800-92 for specific requirements on log rotation and storage dependent on the impact of the web server.'
  desc 'check', 'Interview the ISSO.

Determine if tc Server ALL is using a logging mechanism that is configured to have a capacity large enough to accommodate logging requirements.

If the logging mechanism does not have sufficient capacity, this is a finding.'
  desc 'fix', 'Configure the web server to use a logging mechanism that is configured to allocate log record storage capacity in accordance with NIST SP 800-92 log record storage requirements.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44078r674277_chk'
  tag severity: 'medium'
  tag gid: 'V-240845'
  tag rid: 'SV-240845r674279_rule'
  tag stig_id: 'VRAU-TC-000740'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag fix_id: 'F-44037r674278_fix'
  tag 'documentable'
  tag legacy: ['SV-100771', 'V-90121']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
