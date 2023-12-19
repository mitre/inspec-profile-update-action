control 'SV-109165' do
  title 'The Central Log Server must protect audit information from unauthorized deletion.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. 

Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. Audit information may include data from other applications or be included with the audit application itself.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to protect audit information from unauthorized deletion.

If the Central Log Server is not configured to protect audit information from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to protect audit information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98911r1_chk'
  tag severity: 'medium'
  tag gid: 'V-100061'
  tag rid: 'SV-109165r1_rule'
  tag stig_id: 'SRG-APP-000120-AU-000120'
  tag gtitle: 'SRG-APP-000120-AU-000120'
  tag fix_id: 'F-105745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
