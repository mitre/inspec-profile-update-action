control 'SV-237205' do
  title 'ColdFusion must not store user information in the server registry.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

One way to cause a DoS for ColdFusion is to fill the server hard drive with data or to cause registry purges on a large registry.  Filling the drive with data can be achieved if applications have client management enabled and client data is stored within the registry.  If a scheduled purge is performed on the registry, ColdFusion must load the entire registry into memory and look at each entry to determine if the entry needs to be purged.  The purging process can use all of the available memory and 100% of the CPU for a process that may only delete a few entries.  Also, the registry is typically located on the system partition.  Because of these factors, the use of the registry to store client sessions must not be used.'
  desc 'check', 'Within the Administrator Console, navigate to the "Client Variables" page under the "Server Settings" menu.

If the default storage mechanism for client sessions is set to "Registry", this is a finding.'
  desc 'fix', 'Navigate to the "Client Variables" page under the "Server Settings" menu.  Set the default storage mechanism for client sessions to any available mechanism other than the registry and select the "Apply" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40424r641708_chk'
  tag severity: 'medium'
  tag gid: 'V-237205'
  tag rid: 'SV-237205r641710_rule'
  tag stig_id: 'CF11-05-000182'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40387r641709_fix'
  tag 'documentable'
  tag legacy: ['SV-76973', 'V-62483']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
