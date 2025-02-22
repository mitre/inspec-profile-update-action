control 'SV-202025' do
  title 'The network device must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Determine if the network device protects against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation. This requires logging all administrator access and configuration activity.  This requirement may be verified by demonstration or configuration review. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. (Note that two-factor authentication of administrator access is needed to support this requirement.) If the network device does not protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation. Examples that support this include configuring the audit log to capture administration login events and configuration changes to the network device.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2151r381596_chk'
  tag severity: 'medium'
  tag gid: 'V-202025'
  tag rid: 'SV-202025r539619_rule'
  tag stig_id: 'SRG-APP-000080-NDM-000220'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-2152r539618_fix'
  tag 'documentable'
  tag legacy: ['SV-69331', 'V-55085']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
