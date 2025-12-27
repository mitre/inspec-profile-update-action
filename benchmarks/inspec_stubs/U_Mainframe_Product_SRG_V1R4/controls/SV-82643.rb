control 'SV-82643' do
  title 'The Mainframe Product must automatically audit account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Automatically auditing account enabling actions provides logging that can be used for forensic purposes.
To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings. 

If the Mainframe Product does not automatically audit account creation, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68713r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68153'
  tag rid: 'SV-82643r2_rule'
  tag stig_id: 'SRG-APP-000319-MFP-000047'
  tag gtitle: 'SRG-APP-000319-MFP-000047'
  tag fix_id: 'F-74269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
