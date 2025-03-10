control 'SV-205479' do
  title 'The Mainframe Product must protect audit information from unauthorized deletion.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. 

Some commonly employed methods include: ensuring log files receive the proper file system permissions using file system protections, restricting access, and backing up log data to ensure log data is retained. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. Audit information may include data from other applications or be included with the audit application itself.'
  desc 'check', 'Examine installation and configuration settings.

Verify the Mainframe Product restricts audit information delete access to system programmers, security administrators, and audit personnel.

If access is not restricted, this is a finding.

If an external security manager (ESM) is being used, examine external security configuration and rules.

If the rules do not restrict update or greater access to system programmers, security managers, and audit personnel, this is a finding.'
  desc 'fix', "Verify the Mainframe Product restricts update or greater access to the system's programmers, security administrators, and audit personnel.

This can be accomplished using an ESM.

Configure the Mainframe Product to provide SAF call for audit information access.

Ensure external security manager restricts update or greater access to the system's programmers, security administrators, and audit personnel."
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5745r299670_chk'
  tag severity: 'medium'
  tag gid: 'V-205479'
  tag rid: 'SV-205479r539594_rule'
  tag stig_id: 'SRG-APP-000120-MFP-000176'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-5745r539593_fix'
  tag 'documentable'
  tag legacy: ['SV-82785', 'V-68295']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
