control 'SV-233194' do
  title 'The container platform must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.'
  desc 'The container platform may require external devices be used to fully orchestrate the services needed for users. Examples would be storage or external servers. Without reauthentication, unidentified or unknown devices may be introduced; thereby facilitating malicious activity.

The container platform must be capable of allowing the organization to set requirements associated with device reauthentication. Examples are:

Organizations may require reauthentication of devices, including (but not limited to), the following other situations:

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change;
(iv) After a fixed period of time; or 
(v) Periodically.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.'
  desc 'check', 'Review documentation and configuration to determine if the container platform requires devices to reauthenticate when organization-defined circumstances or situations require reauthentication. 

If the container platform does not require a device to reauthenticate, this is a finding.'
  desc 'fix', 'Configure the container platform to require devices to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36130r599642_chk'
  tag severity: 'medium'
  tag gid: 'V-233194'
  tag rid: 'SV-233194r599643_rule'
  tag stig_id: 'SRG-APP-000390-CTR-000930'
  tag gtitle: 'SRG-APP-000390'
  tag fix_id: 'F-36098r599219_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
