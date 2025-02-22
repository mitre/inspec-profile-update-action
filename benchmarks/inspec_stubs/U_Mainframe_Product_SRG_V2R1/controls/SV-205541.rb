control 'SV-205541' do
  title 'The Mainframe Product must automatically audit account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Automatically auditing account enabling actions provides logging that can be used for forensic purposes.
To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings. 

If the Mainframe Product does not automatically audit account creation, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5807r299856_chk'
  tag severity: 'medium'
  tag gid: 'V-205541'
  tag rid: 'SV-205541r851309_rule'
  tag stig_id: 'SRG-APP-000319-MFP-000047'
  tag gtitle: 'SRG-APP-000319'
  tag fix_id: 'F-5807r299857_fix'
  tag 'documentable'
  tag legacy: ['SV-82643', 'V-68153']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
