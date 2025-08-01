control 'SV-256845' do
  title 'Compliance Guardian must control remote access methods.'
  desc 'Remote access applications (such as those providing remote access to network devices and information systems) which lack automated control capabilities, increase risk, and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include dial-up, broadband, and wireless. 

Remote access applications must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Check the Compliance Guardian Manager configuration to ensure the restriction of inbound connections from nonsecure zones.
- Log on to Compliance Guardian as admin account.
- On the Control Panel page in the System Configuration section, click "General Settings". 
- Select "Security - System Security Policy".
- Verify "Specify network security settings" option.

If "Enable Network Security" is not selected, this is a finding.

If "Enable Network Security" is selected, review the entries under Trusted Network. Verify only known, secure IPs are configured as "Allow".

If "Restricted Network" is selected, review the entries under Restricted Network. 

If IP address restrictions are not configured or IP ranges configured to be allowed are not restrictive enough to prevent connections from nonsecure zones, this is a finding.'
  desc 'fix', 'If needed configure the Compliance Guardian Manager to restrict inbound connections from nonsecure zones.
- Log on to Compliance Guardian as admin account.
- On the Control Panel page in the System Configuration section, click "General Settings". 
- Select "Security - System Security Policy".
- Navigate to "Specify network security settings".
- Select "Enable Network Security" option.
- Add known, secure IPs to allow list of "Trusted Network" option.
- Or, add IPs to block to "Restricted Network" list.
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60520r890143_chk'
  tag severity: 'medium'
  tag gid: 'V-256845'
  tag rid: 'SV-256845r890145_rule'
  tag stig_id: 'APCG-00-000030'
  tag gtitle: 'SRG-APP-000315'
  tag fix_id: 'F-60463r890144_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
