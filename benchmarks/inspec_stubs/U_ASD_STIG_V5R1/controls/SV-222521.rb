control 'SV-222521' do
  title 'The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.'
  desc 'Without reauthenticating devices, unidentified or unknown devices may be introduced; thereby facilitating malicious activity.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of devices, including (but not limited to), the following other situations:

(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) After a fixed period of time;
or
(v) Periodically.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

Gateways and SOA applications are examples of where this requirement would apply.'
  desc 'check', 'Review the application guidance and interview the application administrator.

Identify the methods and manner in which application devices such as an XML gateway, SOA application gateway, or application firewall is allowed to access the application. Most devices themselves will not change role or authenticators once they are established but will need to periodically re-authenticate.

Review the configuration setting in the application where the time period is set to force the device to reauthenticate.

Review local policy requirements to determine if reauthentication intervals are specified.

If the device is not forced to reauthenticate periodically, this is a finding.'
  desc 'fix', 'Configure the application to require reauthentication periodically.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24191r493471_chk'
  tag severity: 'medium'
  tag gid: 'V-222521'
  tag rid: 'SV-222521r508029_rule'
  tag stig_id: 'APSC-DV-001530'
  tag gtitle: 'SRG-APP-000390'
  tag fix_id: 'F-24180r493472_fix'
  tag 'documentable'
  tag legacy: ['SV-84147', 'V-69525']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
