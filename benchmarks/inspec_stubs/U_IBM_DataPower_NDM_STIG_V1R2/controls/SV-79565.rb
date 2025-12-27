control 'SV-79565' do
  title 'The DataPower Gateway must protect audit information from any type of unauthorized read access.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the network device must protect audit information from any and all unauthorized read access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, network devices with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the device interface. If the device provides access to the audit data, the device becomes accountable for ensuring audit information is protected from unauthorized access.'
  desc 'check', 'Login page >> Enter non admin user id and password, select Default for domain >> Click Login. If non admin user can log on, this is a finding.'
  desc 'fix', 'Privileged account user log on to default domain >> Administration >> Access >> User Account >> Select non privileged user account >> Click “…” button next to User Group field >> Enter */default/*?Access=NONE into field >> click add >> click Apply >> click Apply >> click Save Configuration'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65701r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65075'
  tag rid: 'SV-79565r1_rule'
  tag stig_id: 'WSDP-NM-000036'
  tag gtitle: 'SRG-APP-000118-NDM-000235'
  tag fix_id: 'F-71015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
