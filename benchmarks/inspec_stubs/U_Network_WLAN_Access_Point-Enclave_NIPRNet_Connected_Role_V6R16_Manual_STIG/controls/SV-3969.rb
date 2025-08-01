control 'SV-3969' do
  title 'Network devices must only allow SNMP read-only access.'
  desc 'Enabling write access to the device via SNMP provides a mechanism that can be exploited by an attacker to set configuration variables that can disrupt network operations.'
  desc 'check', 'Review the network device configuration and verify SNMP community strings are read-only when using SNMPv1, v2c, or basic v3 (no authentication or privacy). Write access may be used if authentication is configured when using SNMPv3. 

If write-access is used for SNMP versions 1, 2c, or 3-noAuthNoPriv mode and there is no documented approval by the ISSO, this is a finding.'
  desc 'fix', 'Configure the network device to allow for read-only SNMP access when using SNMPv1, v2c, or basic v3 (no authentication or privacy). Write access may be used if authentication is configured when using SNMPv3.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3942r10_chk'
  tag severity: 'medium'
  tag gid: 'V-3969'
  tag rid: 'SV-3969r5_rule'
  tag stig_id: 'NET0894'
  tag gtitle: 'Network element must only allow SNMP read access.'
  tag fix_id: 'F-3902r7_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
