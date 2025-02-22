control 'SV-223479' do
  title 'CA-ACF2 database must be backed up on a scheduled basis.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ACF Command enter:
SET CONTROL(GSO)
SHOW SYSTEMS

If based on the information provided, it can be determined that the ESM database is being backed up on a regularly scheduled basis, this is not a finding.

If it cannot be determined that the ESM database is being backed up on a regularly scheduled basis, this is a finding.'
  desc 'fix', 'Configure ACF2 GSO option to ensure that procedures are in place to back up all ACP files needed for recovery on a scheduled basis.

At a minimum, this means nightly backup of the ACP databases and of other critical security files (such as the ACP parameter file). More frequent backups (two or three times daily) will reduce the time necessary to effect recovery. The ISSO will verify that the backup job(s) run successfully.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25152r504549_chk'
  tag severity: 'medium'
  tag gid: 'V-223479'
  tag rid: 'SV-223479r533198_rule'
  tag stig_id: 'ACF2-ES-000610'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25140r504550_fix'
  tag 'documentable'
  tag legacy: ['V-97657', 'SV-106761']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
