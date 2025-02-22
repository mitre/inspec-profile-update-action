control 'SV-204799' do
  title 'The application server must require devices to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  desc 'Without re-authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of devices, including (but not limited to), the following other situations.

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) After a fixed period of time; or 
(v) Periodically.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server requires devices to re-authenticate when organization-defined circumstances or situations require re-authentication.

If the application server does not require a device to re-authenticate, this is a finding.'
  desc 'fix', 'Configure the application server to require devices to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4919r283044_chk'
  tag severity: 'medium'
  tag gid: 'V-204799'
  tag rid: 'SV-204799r508029_rule'
  tag stig_id: 'SRG-APP-000390-AS-000254'
  tag gtitle: 'SRG-APP-000390'
  tag fix_id: 'F-4919r283045_fix'
  tag 'documentable'
  tag legacy: ['V-57525', 'SV-71801']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
