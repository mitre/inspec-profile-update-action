control 'SV-15459' do
  title 'The network device must not allow SSH Version 1 to be used for administrative access.'
  desc 'SSH Version 1 is a protocol that has never been defined in a standard. Since SSH-1 has inherent design flaws which make it vulnerable to attacks, e.g., man-in-the-middle attacks, it is now generally considered obsolete and should be avoided by explicitly disabling fallback to SSH-1.'
  desc 'check', 'Review the configuration and verify SSH Version 1 is not being used for administrative access.

If the device is using an SSHv1 session, this is a finding.'
  desc 'fix', 'Configure the network device to use SSH version 2.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-12924r8_chk'
  tag severity: 'medium'
  tag gid: 'V-14717'
  tag rid: 'SV-15459r4_rule'
  tag stig_id: 'NET1647'
  tag gtitle: 'The network element must not allow SSH Version 1.'
  tag fix_id: 'F-14184r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
