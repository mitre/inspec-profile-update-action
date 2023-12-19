control 'SV-233195' do
  title 'The container platform must be configured to use multi-factor authentication for user authentication.'
  desc 'Controlling access to the container platform and its components is paramount in having a secure and stable system. Validating users is the first step in controlling the access. Users may be validated by the overall container platform or they may be validated by each component. To standardize and reduce the risks of unauthorized access, the use of multifactor token-based credentials is the preferred method.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Review documentation and configuration to ensure the container platform is configured to use an approved DoD multifactor token (CAC) when accessing platform via user interfaces. 

If multifactor authentication is not configured, this is a finding.'
  desc 'fix', 'Configure the container platform to accept standard DoD multifactor token-based credentials when users interface with the platform.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36131r601072_chk'
  tag severity: 'medium'
  tag gid: 'V-233195'
  tag rid: 'SV-233195r879764_rule'
  tag stig_id: 'SRG-APP-000391-CTR-000935'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-36099r601073_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
