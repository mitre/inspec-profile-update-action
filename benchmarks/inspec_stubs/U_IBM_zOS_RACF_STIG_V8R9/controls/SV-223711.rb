control 'SV-223711' do
  title 'The IBM RACF database must be backed up on a scheduled basis.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Ask the system administrator to determine that procedures exist to back up the security data base and files. Have the system administrator identify the dataset names and frequency of the backups.

If, based on the information provided, it can be determined that the ESM database is being backed up on a regularly scheduled basis, this is not a finding.

If it cannot be determined that the ESM database is being backed up on a regularly scheduled basis, this is a finding.'
  desc 'fix', 'Develop procedures to back up all ACP files needed for recovery on a scheduled basis.

Identify the ACP database and ensure that documented processes are in place to back up its contents on a regularly scheduled basis.

At a minimum, this should include nightly backup of the ACP databases and of other critical security files (such as the ACP parameter file). More frequent backups (two or three times daily) will reduce the time necessary to effect recovery. The ISSO will verify that the backup job(s) run successfully.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25384r514821_chk'
  tag severity: 'medium'
  tag gid: 'V-223711'
  tag rid: 'SV-223711r604139_rule'
  tag stig_id: 'RACF-ES-000640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25372r514822_fix'
  tag 'documentable'
  tag legacy: ['V-98129', 'SV-107233']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
