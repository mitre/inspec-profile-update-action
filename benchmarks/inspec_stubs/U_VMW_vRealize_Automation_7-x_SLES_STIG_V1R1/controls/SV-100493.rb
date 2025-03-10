control 'SV-100493' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful accesses to objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is "enabled", the returned message must contain the following text:

Checking for service auditd                running

If the service is not "running", this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89535r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89843'
  tag rid: 'SV-100493r1_rule'
  tag stig_id: 'VRAU-SL-001430'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-96585r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
