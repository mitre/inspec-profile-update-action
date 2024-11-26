control 'SV-253517' do
  title 'DocAve must control remote access methods.'
  desc 'Remote access applications, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and makes remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Remote access applications must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Check the DocAve Manager configuration to ensure restrict inbound connections from nonsecure zones.
- Log on to DocAve as admin account.
- On the Control Panel page, under System Options, select "Security Settings".
- Navigate to "Network Security" section.

If Enable Network Security is not selected, this is a finding.

If Enable Network Security is selected, review the entries under Trusted Network. Verify only known, secure IPs are configured as Allow.

If IP ranges configured to be Allowed are not restrictive enough to prevent connections from nonsecure zones, this is a finding.'
  desc 'fix', 'Configure the DocAve Manager configuration, if need to restrict inbound connections from nonsecure zones.
- Log on to DocAve as admin account.
- On the Control Panel page, under System Options, select "Security Settings".
- Navigate to "Network Security" section.
- Select "Enable Network Security" option.
- Add known, secure IPs to the Allow list under Trusted Network.
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56969r836524_chk'
  tag severity: 'medium'
  tag gid: 'V-253517'
  tag rid: 'SV-253517r836526_rule'
  tag stig_id: 'DCAV-00-000130'
  tag gtitle: 'SRG-APP-000315'
  tag fix_id: 'F-56920r836525_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
