control 'SV-250578' do
  title 'For systems using DNS resolution, at least two name servers must be configured.'
  desc 'To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab and view the listed DNS server setting(s). 

If DNS is not configured and is not used, this is not a finding.

If DNS is configured with less than 2 servers, this is a finding.'
  desc 'fix', 'Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab and view the listed DNS server setting(s). 

If DNS is configured has less than 2 servers configured, add a second server.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54013r798731_chk'
  tag severity: 'low'
  tag gid: 'V-250578'
  tag rid: 'SV-250578r798733_rule'
  tag stig_id: 'GEN001375-ESXI5-000086'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53967r798732_fix'
  tag 'documentable'
  tag legacy: ['SV-51285', 'V-39427']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
