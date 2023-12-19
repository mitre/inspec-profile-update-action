control 'SV-214084' do
  title 'When updates are applied to PostgreSQL software, any software components that have been replaced or made unnecessary must be removed.'
  desc 'Previous versions of PostgreSQL components that are not removed from the information system after updates have been installed may be exploited by adversaries.

Some PostgreSQL installation tools may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules.

A transition period may be necessary when both the old and the new software are required. This should be taken into account in the planning.'
  desc 'check', 'To check software installed by packages, as the system administrator, run the following command:

# RHEL/CENT Systems
$ sudo rpm -qa | grep postgres

If multiple versions of postgres are installed but are unused, this is a finding.'
  desc 'fix', 'Use package managers (RPM or apt-get) for installing PostgreSQL. Unused software is removed when updated.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15300r360883_chk'
  tag severity: 'medium'
  tag gid: 'V-214084'
  tag rid: 'SV-214084r508027_rule'
  tag stig_id: 'PGS9-00-004300'
  tag gtitle: 'SRG-APP-000454-DB-000389'
  tag fix_id: 'F-15298r360884_fix'
  tag 'documentable'
  tag legacy: ['SV-87569', 'V-72917']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
