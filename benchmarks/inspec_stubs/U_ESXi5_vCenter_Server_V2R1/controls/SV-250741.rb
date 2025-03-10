control 'SV-250741' do
  title 'Network access to the vCenter Server system must be restricted.'
  desc 'Restrict access to only those essential components required to communicate with vCenter. Blocking access by unnecessary systems reduces the potential for general attacks on the operating system and minimizes risk.'
  desc 'check', 'The vCenter Server must be protected by a network and/or local firewall on the vCenter Server Windows system. This protection must include IP-based access restrictions, enabling only necessary components to communicate with the vCenter Server system.

If the vCenter Server Windows system is not protected by a network and/or local firewall, this is a finding.'
  desc 'fix', 'The vCenter Server Windows system must be protected by utilizing a network and/or local firewall. Install the vCenter Server Windows system behind the firewall and/or install a firewall application on the Windows system. Firewall protections must include IP-based access restrictions, enabling only necessary components to communicate with the vCenter Server system.'
  impact 0.3
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54176r799911_chk'
  tag severity: 'low'
  tag gid: 'V-250741'
  tag rid: 'SV-250741r799913_rule'
  tag stig_id: 'VCENTER-000022'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54130r799912_fix'
  tag 'documentable'
  tag legacy: ['V-39560', 'SV-51418']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
