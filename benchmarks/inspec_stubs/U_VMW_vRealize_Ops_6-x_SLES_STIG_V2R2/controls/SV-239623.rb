control 'SV-239623' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful attempts to delete security levels occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service   auditd   running

If the service is not running, this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42856r662318_chk'
  tag severity: 'medium'
  tag gid: 'V-239623'
  tag rid: 'SV-239623r662320_rule'
  tag stig_id: 'VROM-SL-001370'
  tag gtitle: 'SRG-OS-000467-GPOS-00211'
  tag fix_id: 'F-42815r662319_fix'
  tag 'documentable'
  tag legacy: ['SV-99367', 'V-88717']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
