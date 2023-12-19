control 'SV-206448' do
  title 'The Central Log Server must be configured to protect the data sent from hosts and devices from being altered in a way that may prevent the attribution of an action to an individual (or process acting on behalf of an individual).'
  desc 'Without non-repudiation, it is impossible to positively attribute an action to an individual (or process acting on behalf of an individual).

The records stored by the Central Log Server must be protected against such alteration as removing the identifier. A hash is one way of performing this function. The server must not allow the removal of identifiers or date/time, or it must severely restrict the ability to do so. Additionally, the log administrator access and activity with the user account information.'
  desc 'check', 'Examine the configuration.

Verify the system is configured with a hash or other method that protects the data against alteration of the log information sent from hosts and devices.

Verify the Central Log Server is configured to log all changes to the machine data.

If the Central Log Server is not configured to protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to use a hash or other method that protects the data against alteration of the log information sent from hosts and devices.

Configure the Central Log Server to not allow alterations to the machine data.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6708r285588_chk'
  tag severity: 'medium'
  tag gid: 'V-206448'
  tag rid: 'SV-206448r395691_rule'
  tag stig_id: 'SRG-APP-000080-AU-000010'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-6708r285589_fix'
  tag 'documentable'
  tag legacy: ['SV-95819', 'V-81105']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
