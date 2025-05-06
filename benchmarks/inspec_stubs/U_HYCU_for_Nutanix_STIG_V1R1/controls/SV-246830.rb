control 'SV-246830' do
  title 'The HYCU VM console and HYCU Web UI must be configured to use an authentication server for authenticating users prior to granting access to protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined requirements.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is a particularly important protection against the insider threat. This requirement supports non-repudiation of actions taken by an individual and is required in order to maintain the integrity of the configuration management process. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device.

"
  desc 'check', 'Configure Active Directory authentication by adding one or more Active Directories as authentication sources in HYCU. 

This allows users to log on to the HYCU web user interface with their Active Directory domain accounts or, if certificate authentication is enabled, with a client certificate or a smart card (CAC authentication).

Log on to the HYCU Web UI, select the gear menu, and then choose the Active Directory option.

Verify that at least one Active Directory authentication server is configured. 

If no Active Directory is configured, this is a finding.

When using certificate authentication using client certificate or smart card (CAC authentication), verify "Enable Certification Authentication" is enabled. 

If "Enable Certification Authentication" is not enabled, this is a finding.'
  desc 'fix', 'Log on to the HYCU Web UI, select the gear menu, and choose the "Active Directory" option.

Configure Active Directory by specifying needed LDAP strings to allow HYCU to use AD users and groups for access to the Web UI.

When using certificate authentication using client certificate or smart card (CAC authentication), ensure "Service Account" is specified in the Active Directory configuration and "Enable Certification Authentication" is enabled.'
  impact 0.7
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50262r768152_chk'
  tag severity: 'high'
  tag gid: 'V-246830'
  tag rid: 'SV-246830r768242_rule'
  tag stig_id: 'HYCU-AU-000001'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-50216r768153_fix'
  tag satisfies: ['SRG-APP-000080-NDM-000220', 'SRG-APP-000149-NDM-000247', 'SRG-APP-000175-NDM-000262', 'SRG-APP-000177-NDM-000263', 'SRG-APP-000516-NDM-000336']
  tag 'documentable'
  tag cci: ['CCI-000166', 'CCI-000366', 'CCI-000370', 'CCI-000765']
  tag nist: ['AU-10', 'CM-6 b', 'CM-6 (1)', 'IA-2 (1)']
end
