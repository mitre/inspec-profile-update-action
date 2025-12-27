control 'SV-233190' do
  title 'All non-essential, unnecessary, and unsecure DoD ports, protocols, and services must be disabled in the container platform.'
  desc 'To properly offer services to the user and to orchestrate containers, the container platform may offer services that use ports and protocols that best fit those services. The container platform, when offering the services, must only offer the services on ports and protocols authorized by the DoD.

To validate that the services are using only the approved ports and protocols, the organization must perform a periodic scan/review of the container platform and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'Review the container platform configuration to determine if services or capabilities presently on the information system are required for operational or mission needs. 

If additional services or capabilities are present on the system, this is a finding.'
  desc 'fix', 'Configure the container platform to only utilize secure ports and protocols required for operation that have been accepted for use as per the Ports, Protocols, and Services Category Assignments List (CAL) from DISA (PPSM).'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36126r599206_chk'
  tag severity: 'medium'
  tag gid: 'V-233190'
  tag rid: 'SV-233190r599509_rule'
  tag stig_id: 'SRG-APP-000383-CTR-000910'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-36094r599207_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
