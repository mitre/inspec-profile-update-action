control 'SV-222524' do
  title 'The application must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

Ask the application administrator to log on to the application. Have the application admin use their non-privileged credentials.

Validate the application prompts the user to provide a certificate from the CAC.

If the application allows access without requiring a CAC, this is a finding.'
  desc 'fix', 'Configure the application to require CAC authentication.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24194r493480_chk'
  tag severity: 'medium'
  tag gid: 'V-222524'
  tag rid: 'SV-222524r508029_rule'
  tag stig_id: 'APSC-DV-001560'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-24183r493481_fix'
  tag 'documentable'
  tag legacy: ['SV-84153', 'V-69531']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
