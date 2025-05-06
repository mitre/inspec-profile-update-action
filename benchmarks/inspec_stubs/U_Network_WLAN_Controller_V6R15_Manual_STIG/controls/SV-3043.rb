control 'SV-3043' do
  title 'The network device must use different SNMP community names or groups for various levels of read and write access.'
  desc 'Numerous vulnerabilities exist with SNMP; therefore, without unique SNMP community names, the risk of compromise is dramatically increased. This is especially true with vendors default community names which are widely known by hackers and other networking experts. If a hacker gains access to these devices and can easily guess the name, this could result in denial of service, interception of sensitive information, or other destructive actions.'
  desc 'check', 'Review the SNMP configuration of all managed nodes to ensure different community names (V1/2) or groups/users (V3) are configured for read-only and read-write access.

If unique community strings or accounts are not used for SNMP peers, this is a finding.'
  desc 'fix', 'Configure the SNMP community strings on the network device and change them from the default values. SNMP community strings and user passwords must be unique and not match any other network device passwords. Different community strings (V1/2) or groups (V3) must be configured for various levels of read and write access.'
  impact 0.5
  ref 'DPMS Target WLAN Controller'
  tag check_id: 'C-3825r7_chk'
  tag severity: 'medium'
  tag gid: 'V-3043'
  tag rid: 'SV-3043r4_rule'
  tag stig_id: 'NET1675'
  tag gtitle: 'SNMP privileged and non-privileged access.'
  tag fix_id: 'F-3068r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
