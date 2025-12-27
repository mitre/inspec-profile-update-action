control 'SV-225430' do
  title 'The HBSS McAfee Agent must be installed.'
  desc 'The McAfee Agent is the client side distributed component of McAfee ePolicy Orchestrator (McAfee ePO) which provides a secure communication channel between the ePO server and managed point products.'
  desc 'check', 'Run "Services.msc".

Verify the McAfee Agent service is running, depending on the version installed.

Version - Service Name
McAfee Agent v5.x - McAfee Agent Service
McAfee Agent v4.x - McAfee Framework Service

If the service is not listed or does not have a Status of "Started", this is a finding.'
  desc 'fix', 'Deploy the McAfee Agent as detailed in accordance with the DoD HBSS STIG.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27129r471632_chk'
  tag severity: 'medium'
  tag gid: 'V-225430'
  tag rid: 'SV-225430r569185_rule'
  tag stig_id: 'WN12-GE-000019'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-27117r471633_fix'
  tag 'documentable'
  tag legacy: ['SV-53010', 'V-15505']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
