control 'SV-96867' do
  title 'The MaaS360 MDM server must be configured to transfer MaaS360 MDM server logs to another server for storage, analysis, and reporting.

Note: MaaS360 MDM server logs include logs of MDM events and logs transferred to the MaaS360 MDM server by MDM agents of managed devices.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. Since the MaaS360 MDM server has limited capability to store mobile device log files and perform analysis and reporting of mobile device log files, the MaaS360 MDM server must have the capability to transfer log files to an audit log management server.

SFR ID: FMT_SMF.1.1(2) b
FAU_STG_EXT.1.1(1)'
  desc 'check', 'Verify the site has set up access to web services to extract server logs.

If the site has not set up access to server logs so the logs can be stored on another server for analysis and reporting, this is a finding.'
  desc 'fix', 'The site system administrator must communicate with IBM to get access to web services to extract server logs.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82153'
  tag rid: 'SV-96867r1_rule'
  tag stig_id: 'M360-10-006300'
  tag gtitle: 'PP-MDM-311054'
  tag fix_id: 'F-89007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
