control 'SV-3070' do
  title 'Network devices must log all attempts to establish a management connection for administrative access.'
  desc 'Audit logs are necessary to provide a trail of evidence in case the network is compromised.  Without an audit trail that provides a when, where, who and how set of information, repeat offenders could continue attacks against the network indefinitely.  With this information, the network administrator can devise ways to block the attack and possibly identify and prosecute the attacker.'
  desc 'check', 'Review the configuration to verify all attempts to access the device via management connection are logged.

If management connection attempts are not logged, this is a finding.'
  desc 'fix', 'Configure the device to log all access attempts to the device to establish a management connection for administrative access.'
  impact 0.3
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-3542r6_chk'
  tag severity: 'low'
  tag gid: 'V-3070'
  tag rid: 'SV-3070r4_rule'
  tag stig_id: 'NET1640'
  tag gtitle: 'Management connections must be logged.'
  tag fix_id: 'F-3095r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
