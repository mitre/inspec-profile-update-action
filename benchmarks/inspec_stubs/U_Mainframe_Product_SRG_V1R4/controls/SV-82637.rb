control 'SV-82637' do
  title 'The Mainframe Product must notify system programmers and security administrators when accounts are modified.'
  desc 'When application accounts are modified, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the application processes themselves. Sending notification of account modification events to the system administrator (SA) and information system security officer (ISSO) is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If the Mainframe Product does not notify system programmers and security administrators when accounts are modified, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to notify system programmers and security administrators when accounts are modified.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68147'
  tag rid: 'SV-82637r2_rule'
  tag stig_id: 'SRG-APP-000292-MFP-000044'
  tag gtitle: 'SRG-APP-000292-MFP-000044'
  tag fix_id: 'F-74263r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
