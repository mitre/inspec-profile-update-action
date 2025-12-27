control 'SV-243489' do
  title 'Read-only Domain Controller (RODC) architecture and configuration must comply with directory services requirements.'
  desc "The RODC role provides a unidirectional replication method for selected information from your internal network to the DMZ. If not properly configured so that the risk footprint is minimized, the interal domain controller or forest can be compromised.

RODC is considered part of the site's Forest or Domain installation since it is not a standalone product, but rather a role of the the Windows AD DS full installation or Server Core installation. It is possible to have Windows 2003 clients authenticated using RODC, however, compatibility packs are needed. 

Note that RODC is not authorized for use across the site's perimeter firewall."
  desc 'check', '1. Verify that the site has applied the Network Infrastucture STIG to configure the VPN and IPSec. 

2. Verify that IPSec and other communications and security configurations for the management and replication of the RODC will be managed by use of the minimum required Group Policy Objects (GPOs).

3. Include an inspection of the RODC server in the DMZ when inspection for least privilege.

4. Verify that required patches and compatibility packs are installed if RODC is used with Windows 2003 (or earlier) clients.

5. If RODC server and configuration does not comply with requirements, then this is a finding.'
  desc 'fix', '1. Ensure compliance with VPN and IPSec requirements in the Network Insfrastucture STIG. 

2. Ensure IPSec and other communications and security configurations for the management and replication of the RODC uses the minimum required Group Policy Objects (GPOs) to provide the required functionality.

3. Replicate only the information needed to provide the functionality required. If full replication of all directory data is not needed, then replicated selective ID and authentication information as needed to the RODC.

4. Include an inspection of the RODC server in the DMZ when inspection for least privilege.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46764r723500_chk'
  tag severity: 'medium'
  tag gid: 'V-243489'
  tag rid: 'SV-243489r723564_rule'
  tag stig_id: 'AD.0270'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46721r723501_fix'
  tag 'documentable'
  tag legacy: ['V-25997', 'SV-32648']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
