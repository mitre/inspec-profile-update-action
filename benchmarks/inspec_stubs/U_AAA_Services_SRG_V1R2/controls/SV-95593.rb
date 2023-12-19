control 'SV-95593' do
  title 'AAA Services must be configured to use at least two NTP servers to synchronize time.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. 

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose. Synchronizing the internal clock using NTP provides uniformity for all system clocks over a network. NTP provides an efficient and scalable method for network devices to synchronize to an accurate time source.'
  desc 'check', 'Verify AAA Services are configured to use at least two NTP servers to synchronize time. Both a primary and backup NTP server must be identified in the configuration. AAA Services may leverage the capability of an operating system.

If AAA Services are not configured to use at least two separate NTP servers, this is a finding.'
  desc 'fix', 'Configure AAA Services to use two separate NTP servers. Both a primary and backup NTP server must be identified in the configuration.'
  impact 0.3
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80619r1_chk'
  tag severity: 'low'
  tag gid: 'V-80883'
  tag rid: 'SV-95593r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000350'
  tag gtitle: 'SRG-APP-000516-AAA-000350'
  tag fix_id: 'F-87737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001891']
  tag nist: ['CM-6 b', 'AU-8 (1) (a)']
end
