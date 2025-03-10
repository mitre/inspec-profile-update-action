control 'SV-239621' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service auditd                running

If the service is not running, this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42854r662312_chk'
  tag severity: 'medium'
  tag gid: 'V-239621'
  tag rid: 'SV-239621r662314_rule'
  tag stig_id: 'VROM-SL-001360'
  tag gtitle: 'SRG-OS-000465-GPOS-00209'
  tag fix_id: 'F-42813r662313_fix'
  tag 'documentable'
  tag legacy: ['SV-99363', 'V-88713']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
