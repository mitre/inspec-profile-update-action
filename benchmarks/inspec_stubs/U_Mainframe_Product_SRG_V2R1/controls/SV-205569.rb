control 'SV-205569' do
  title 'The Mainframe Product must require devices to reauthenticate when circumstances or situations require reauthentication as defined in site security plan.'
  desc 'Without reauthenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of devices, including (but not limited to), the following other situations.

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change;
(iv) After a fixed period of time; or 
(v) Periodically.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

Gateways and SOA applications are examples of where this requirement would apply.'
  desc 'check', 'If the Mainframe Product has no function or capability for device logon, this is not applicable. 

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations.

If the Mainframe Product is configured to require devices to reauthenticate when circumstances or situations require reauthentication as defined in site security plan, this is not a finding.'
  desc 'fix', 'Configure the Mainframe Product to require devices to reauthenticate when circumstances or situations require reauthentication as defined in site security plan.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5835r299934_chk'
  tag severity: 'medium'
  tag gid: 'V-205569'
  tag rid: 'SV-205569r851335_rule'
  tag stig_id: 'SRG-APP-000390-MFP-000205'
  tag gtitle: 'SRG-APP-000390'
  tag fix_id: 'F-5835r299935_fix'
  tag 'documentable'
  tag legacy: ['SV-82819', 'V-68329']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
