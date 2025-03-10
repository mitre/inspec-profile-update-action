control 'SV-99369' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful attempts to delete security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'To verify that auditing is configured for system administrator actions, run the following command: 

# auditctl -l | grep "watch=/etc/sudoers"

The result should return a rule for sudoers, such as: 

LIST_RULES: exit,always watch=/etc/sudoers perm=wa key=sudoers

If there is no output, this is a finding.'
  desc 'fix', 'At a minimum, the SLES for vRealize audit system should collect administrator actions for all users and root. Add the following to the "/etc/audit/audit.rules" file: 

-w /etc/sudoers -p wa -k sudoers

OR

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88411r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88719'
  tag rid: 'SV-99369r1_rule'
  tag stig_id: 'VROM-SL-001375'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-95461r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
