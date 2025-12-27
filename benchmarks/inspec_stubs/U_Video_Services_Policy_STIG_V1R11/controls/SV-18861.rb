control 'SV-18861' do
  title 'The VTC system and components must not have default or factory passwords.'
  desc 'Factory default, well-known, and manufacturer backdoor accounts and their associated passwords provide easy unauthorized access to systems and devices. Leaving such accounts and passwords active on a system or device makes it extremely vulnerable to attack and unauthorized access. As such, they must be removed, changed, renamed, or otherwise disabled.

Also covered by this policy are “community strings”, which act as passwords for monitoring and management of network devices and attached systems via SNMP. The universal default SNMP community strings are “public” and private” and are well known. 

Default access for VTC operation, local and remote control, management, and configuration purposes is typically unrestricted or minimally protected by well-known default passwords. It has been demonstrated that not changing these passwords is the most common cause of VTC system compromise.'
  desc 'check', 'Review site documentation to confirm VTC system and component default and factory passwords have been changed. This includes SNMP community strings must be changed or replaced prior to the VTU being placed into service. If the VTC system and component default and factory passwords are not changed, this is a finding.

Note: During APL testing, this is a finding in the event default passwords cannot be changed on VTC or VTU.'
  desc 'fix', 'Implement changing all VTC system and component default and factory passwords.'
  impact 0.7
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18957r2_chk'
  tag severity: 'high'
  tag gid: 'V-17687'
  tag rid: 'SV-18861r2_rule'
  tag stig_id: 'RTS-VTC 2020.00'
  tag gtitle: 'RTS-VTC 2020'
  tag fix_id: 'F-17584r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
