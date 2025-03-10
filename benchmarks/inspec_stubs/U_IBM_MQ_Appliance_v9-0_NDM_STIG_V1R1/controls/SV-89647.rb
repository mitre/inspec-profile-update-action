control 'SV-89647' do
  title 'The MQ Appliance network device must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised. 

MQ Appliance network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
config 
crypto 
show crypto-mode 

The result should be: fips-140-2-l1 

If it is not, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. Enable FIPS 140-2 Level 1 mode at the next reload of the firmware. 

Enter: 
config 
crypto 
crypto-mode-set fips-140-2-l1 

The following message will appear: 
"Crypto Mode Successfully set to fips-140-2-l1 for next boot."'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74973'
  tag rid: 'SV-89647r1_rule'
  tag stig_id: 'MQMH-ND-000720'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-81589r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
