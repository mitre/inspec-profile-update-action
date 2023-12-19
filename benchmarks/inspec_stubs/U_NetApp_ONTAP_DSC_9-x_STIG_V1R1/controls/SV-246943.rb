control 'SV-246943' do
  title 'ONTAP must generate log records for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Use "cluster log-forwarding show -instance" to see if remote syslogging of ONTAP audit records is configured and which syslog facilities are being forwarded.

If ONTAP cannot be configured to generate log records for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Configure ONTAP to generate log records for a locally developed list of auditable events with "cluster log-forwarding create -destination <hostname_or_ip_address> -facility <localx>" where x is the number of the local facility.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50375r769159_chk'
  tag severity: 'medium'
  tag gid: 'V-246943'
  tag rid: 'SV-246943r769161_rule'
  tag stig_id: 'NAOT-CM-000006'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-50329r769160_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000169']
  tag nist: ['CM-6 b', 'AU-12 a']
end
