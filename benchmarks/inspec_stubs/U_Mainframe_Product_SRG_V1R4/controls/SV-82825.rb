control 'SV-82825' do
  title 'The Mainframe Product must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'If the Mainframe Product uses an external security manager for all account management, this is not applicable.

Examine user account management configurations.
 
If the Mainframe Product  account management is not configured to accept PIV credentials, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to accept PIV credentials.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68895r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68335'
  tag rid: 'SV-82825r1_rule'
  tag stig_id: 'SRG-APP-000391-MFP-000208'
  tag gtitle: 'SRG-APP-000391-MFP-000208'
  tag fix_id: 'F-74449r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
