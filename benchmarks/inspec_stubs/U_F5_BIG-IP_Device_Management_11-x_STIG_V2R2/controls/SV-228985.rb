control 'SV-228985' do
  title 'The BIG-IP appliance must be configured to protect audit information from any type of unauthorized read access.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the network device must protect audit information from any and all unauthorized read access.

This requirement can be achieved through multiple methods that will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, network devices with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the device interface. If the device provides access to the audit data, the device becomes accountable for ensuring audit information is protected from unauthorized access.'
  desc 'check', 'Verify the BIG-IP appliance is configured to protect audit information from any type of unauthorized read access. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Verify authorized access is configured for each role under "Log Access".

If the BIG-IP appliance does not protect audit information from any type of unauthorized read access, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to protect audit information from any type of unauthorized read access.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31300r518001_chk'
  tag severity: 'medium'
  tag gid: 'V-228985'
  tag rid: 'SV-228985r879887_rule'
  tag stig_id: 'F5BI-DM-000073'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31277r518002_fix'
  tag 'documentable'
  tag legacy: ['SV-74557', 'V-60127']
  tag cci: ['CCI-000366', 'CCI-000162']
  tag nist: ['CM-6 b', 'AU-9 a']
end
