control 'SV-207236' do
  title 'When communications with the Central Log Server is lost, the VPN Gateway must continue to queue traffic log records locally.'
  desc 'If the system were to continue processing after audit failure, actions can be taken on the system that cannot be tracked and recorded for later forensic analysis.

Because of the importance of ensuring mission/business continuity, organizations may determine that the nature of the audit failure is not so severe that it warrants a complete shutdown of the application supporting the core organizational missions/business operations. In those instances, partial application shutdowns or operating in a degraded mode with reduced capability may be viable alternatives.

This requirement only applies to components where this is specific to the function of the device (e.g., IDPS sensor logs, firewall logs). This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify that in the event that communications with the Central Log Server is lost, the VPN Gateway is configured to continue to queue traffic log records locally.

If the VPN Gateway does not continue to queue traffic log records locally when communications with the Central Log Server is lost, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to continue to queue traffic log records locally when communications with the Central Log Server is lost.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7496r378329_chk'
  tag severity: 'medium'
  tag gid: 'V-207236'
  tag rid: 'SV-207236r856708_rule'
  tag stig_id: 'SRG-NET-000336-VPN-001280'
  tag gtitle: 'SRG-NET-000336'
  tag fix_id: 'F-7496r378330_fix'
  tag 'documentable'
  tag legacy: ['SV-106289', 'V-97151']
  tag cci: ['CCI-001861']
  tag nist: ['AU-5 (4)']
end
