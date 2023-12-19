control 'SV-222525' do
  title 'The application must electronically verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.

If the application does not verify the credentials provided, user authentication cannot be established which places the integrity and confidentiality of the application at risk.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

Ask the application administrator to log on to the application.

Validate the application prompts the user to provide a certificate from the CAC.

Validate the application requests the user to input their CAC PIN.

If the application allows access without requiring a CAC, this is a finding.'
  desc 'fix', 'Configure the application to require CAC authentication.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24195r493483_chk'
  tag severity: 'medium'
  tag gid: 'V-222525'
  tag rid: 'SV-222525r849459_rule'
  tag stig_id: 'APSC-DV-001570'
  tag gtitle: 'SRG-APP-000392'
  tag fix_id: 'F-24184r493484_fix'
  tag 'documentable'
  tag legacy: ['SV-84155', 'V-69533']
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
