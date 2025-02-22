control 'SV-95523' do
  title 'The SDN controller must be configured to audit the enforcement actions used to restrict access associated with changes to any application within the SDN framework.'
  desc 'Without auditing the enforcement of access restrictions against changes to any application within the SDN framework, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to audit enforcement actions used to restrict access associated with changes to any application. 

If the SDN controller is not configured to audit the enforcement actions used to restrict access associated with changes to any application within the SDN framework, this is a finding.'
  desc 'fix', 'Configure the SDN controller to audit enforcement actions used to restrict access associated with changes to any application.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80549r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80813'
  tag rid: 'SV-95523r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001100'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
