control 'SV-222630' do
  title 'The Configuration Management (CM) repository must be properly patched and STIG compliant.'
  desc 'A Configuration Management (CM) repository is used to manage application code versions and to securely store application code.

Failure to properly apply security patches and secure the software Configuration Management system could affect the confidentiality and integrity of the application source-code.  

Compromise of the Configuration Management system could lead to unauthorized changes to applications including the addition of malware, root kits, back doors, logic bombs or other malicious functions into valid application code.   

This requirement is intended to be applied to application developers or organizations responsible for code management or who have and operate an application CM repository.'
  desc 'check', 'Review the application system documentation and interview the application administrator.

Identify if the STIG is being applied to application developers or organizations responsible for code management or who have and operate an application CM repository. If this is not the case, the requirement is not applicable.

Review CM patch management processes and procedures.  Have the system and CM admins demonstrate their patch management processes and verify the system has the latest security patches applied.  

Review the ATO documentation and verify the system that operates the CM repository software has had all relevant STIGs applied.

If CM repository is not at the latest security patch level and is not operating on a STIG compliant system, this is a finding.'
  desc 'fix', 'Patch the CM system when new security patches are made available and apply the relevant STIGs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24300r493798_chk'
  tag severity: 'medium'
  tag gid: 'V-222630'
  tag rid: 'SV-222630r879887_rule'
  tag stig_id: 'APSC-DV-002995'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24289r493799_fix'
  tag 'documentable'
  tag legacy: ['SV-84961', 'V-70339']
  tag cci: ['CCI-001795']
  tag nist: ['CM-9 b']
end
